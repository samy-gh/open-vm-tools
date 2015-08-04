/*********************************************************
 * Copyright (C) 2004 VMware, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation version 2 and no later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 *********************************************************/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define CO_DO_ZERO_COPY
#define CO_DO_TSO
#define CO_USE_TICK
#define CO_USE_NEW_ALTQ

/*
 * FreeBSD 5.3 introduced an MP-safe (multiprocessor-safe) network stack.
 * I.e., drivers must either request Giant's protection or handle locking
 * themselves.  For performance reasons, the vmxnet driver is now MPSAFE.
 */
#if __FreeBSD_version >= 503000
#   define VXN_MPSAFE
#   include <sys/lock.h>
#   include <sys/mutex.h>
#endif

/*
 * FreeBSD 7.0-RELEASE changed the bus_setup_intr API to include a device_filter_t
 * parameter.
 */
#if __FreeBSD_version >= 700031
#   define VXN_NEWNEWBUS
#endif

#if __FreeBSD_version < 600000
#include <machine/bus_pio.h>
#else
#include <net/if_types.h>
#endif
#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/clock.h>

#include <sys/module.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/bpf.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#if __FreeBSD__ >= 5
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#else
#include <pci/pcireg.h>
#include <pci/pcivar.h>
#endif

/* define INLINE the way gcc likes it */
#define INLINE __inline__

#ifndef VMX86_TOOLS
#define VMX86_TOOLS
#endif
#include "vm_basic_types.h"
#include "vmxnet_def.h"
#include "vmxnet2_def.h"
#include "vm_device_version.h"
#include "net_compat.h"


#define VMXNET_ID_STRING "VMware PCI Ethernet Adpater"
#define CRC_POLYNOMIAL_LE 0xedb88320UL  /* Ethernet CRC, little endian */
#define ETHER_ALIGN  2
#define VMXNET_MIN_MTU                  (ETHERMIN - 14)
#define VMXNET_MAX_MTU                  (16 * 1024 - 18)
#define VMXNET_CSUM_FEATURES            (CSUM_TCP | CSUM_UDP)
   

/* number of milliseconds to wait for pending transmits to complete on stop */
#define MAX_TX_WAIT_ON_STOP 2000

static int vxn_probe (device_t);
static int vxn_attach (device_t);
static int vxn_detach (device_t);

typedef struct vxn_softc {
#ifdef VXN_NEEDARPCOM
   struct arpcom            arpcom;
#else
   struct ifnet            *vxn_ifp;
   struct ifmedia           media;
#endif
#ifdef VXN_MPSAFE
   struct mtx               vxn_mtx;
#endif
#ifdef CO_USE_TICK
   struct callout           vxn_stat_ch;
#endif
   struct resource         *vxn_io;
   bus_space_handle_t	    vxn_iobhandle;
   bus_space_tag_t	    vxn_iobtag;
   struct resource         *vxn_irq;
   void			   *vxn_intrhand;
   Vmxnet2_DriverData      *vxn_dd;
   uint32                   vxn_dd_phys;
   int                      vxn_num_rx_max_bufs;
   int                      vxn_num_rx_max_bufs2;
   int                      vxn_num_tx_max_bufs;
   int                      vxn_num_rx_bufs;
   int                      vxn_num_rx_bufs2;
   int                      vxn_num_tx_bufs;
   Vmxnet2_RxRingEntry     *vxn_rx_ring;
   Vmxnet2_RxRingEntry     *vxn_rx_ring2;
   Vmxnet2_TxRingEntry     *vxn_tx_ring;
   int                      vxn_tx_pending;
   int                      vxn_rings_allocated;
   uint32                   vxn_max_tx_frags;
   uint32                   vxn_zero_copy_tx;
   boolean_t                vxn_chain_tx;
   boolean_t                vxn_chain_rx;
   uint32                   vxn_csum_tx_req_cnt;
   uint32                   vxn_csum_rx_ok_cnt;
   uint32                   vxn_capabilities;
   uint32                   vxn_features;

   int                      vxn_timer;

   struct mbuf             *vxn_tx_buffptr[VMXNET2_MAX_NUM_TX_BUFFERS_TSO];
   struct mbuf             *vxn_rx_buffptr[ENHANCED_VMXNET2_MAX_NUM_RX_BUFFERS];
   struct mbuf             *vxn_rx_buffptr2[VMXNET2_MAX_NUM_RX_BUFFERS2];

} vxn_softc_t;

/*
 * Driver entry points
 */
static void vxn_init(void *);
static void vxn_link_check( vxn_softc_t *sc );
static void vxn_start(struct ifnet *);
static int vxn_ioctl(struct ifnet *, u_long, caddr_t);
#ifdef CO_USE_TICK
static void vxn_watchdog(struct ifnet *);
static void vxn_tick(void *xsc);
#else
#  if __FreeBSD_version < 900000
static void vxn_watchdog(struct ifnet *);
#  endif
#endif
static void vxn_intr (void *);

static void vxn_rx(vxn_softc_t *sc);
static void vxn_tx_complete(vxn_softc_t *sc);
static int vxn_init_rings(vxn_softc_t *sc);
static void vxn_release_rings(vxn_softc_t *);
static void vxn_stop(vxn_softc_t *);

/*
 * Locked counterparts above functions
 */
static void vxn_initl(vxn_softc_t *);
static void vxn_startl(struct ifnet *);
static void vxn_stopl(vxn_softc_t *);

static device_method_t vxn_methods[] = {
   DEVMETHOD(device_probe,	vxn_probe),
   DEVMETHOD(device_attach,	vxn_attach),
   DEVMETHOD(device_detach,	vxn_detach),

   { 0, 0 }
};

static driver_t vxn_driver = {
   "vxn",
   vxn_methods,
   sizeof(struct vxn_softc)
};

static devclass_t vxn_devclass;

MODULE_DEPEND(if_vxn, pci, 1, 1, 1);
MODULE_DEPEND(if_vxn, ether, 1, 1, 1);
DRIVER_MODULE(if_vxn, pci, vxn_driver, vxn_devclass, 0, 0);

/*
 *-----------------------------------------------------------------------------
 * vxn_probe --
 *      Probe device. Called when module is loaded
 *
 * Results:
 *      Returns 0 for success, negative errno value otherwise.
 *
 * Side effects:
 *      Register device name with OS
 *-----------------------------------------------------------------------------
 */
static int
vxn_probe(device_t dev)
{
   if ((pci_get_vendor(dev) == PCI_VENDOR_ID_VMWARE) &&
       (pci_get_device(dev) == PCI_DEVICE_ID_VMWARE_NET)) {
      device_set_desc(dev, VMXNET_ID_STRING);
      return 0;
   }

   return ENXIO;
}

/*
 *-----------------------------------------------------------------------------
 * vxn_execute_4 --
 *      Execute command returing 4 bytes on vmxnet.  Used to retrieve
 *      number of TX/RX buffers and to get hardware capabilities and
 *      features.
 *
 * Results:
 *      Returns value reported by hardware.
 *
 * Side effects:
 *      All commands supported are read-only, so no side effects.
 *-----------------------------------------------------------------------------
 */
static u_int32_t
vxn_execute_4(const vxn_softc_t *sc,	/* IN: adapter */
              u_int32_t cmd)		/* IN: command */
{
   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                     VMXNET_COMMAND_ADDR, cmd);
   return bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                           VMXNET_COMMAND_ADDR);
}

static int
vxn_check_link(vxn_softc_t *sc)
{
   uint32 status;
   int ok;

   status = bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_STATUS_ADDR);
   ok = (status & VMXNET_STATUS_CONNECTED) != 0;
   return ok;
}

/*
 *-----------------------------------------------------------------------------
 *
 * vxn_media_status --
 *
 *      This routine is called when the user quries the status of interface
 *      using ifconfig. Checks link state and updates media state accorgingly.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

static void
vxn_media_status(struct ifnet * ifp, struct ifmediareq * ifmr)
{
   vxn_softc_t *sc = ifp->if_softc;
   int connected = 0;

   VXN_LOCK((vxn_softc_t *)ifp->if_softc);
   connected = vxn_check_link(sc);

   ifmr->ifm_status = IFM_AVALID;
   ifmr->ifm_active = IFM_ETHER;

   if (!connected) {
      ifmr->ifm_status &= ~IFM_ACTIVE;
      VXN_UNLOCK((vxn_softc_t *)ifp->if_softc);
      return;
   }

   ifmr->ifm_status |= IFM_ACTIVE;

   VXN_UNLOCK((vxn_softc_t *)ifp->if_softc);
   return;
}


/*
 *-----------------------------------------------------------------------------
 *
 * vxn_media_change --
 *
 *      This routine is called when the user changes speed/duplex using
 *      media/mediopt option with ifconfig.
 *
 * Results:
 *      Returns 0 for success, error code otherwise.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

static int
vxn_media_change(struct ifnet * ifp)
{
   vxn_softc_t *sc = ifp->if_softc;
   struct ifmedia *ifm = &sc->media;

   if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
      return (EINVAL);

   if (IFM_SUBTYPE(ifm->ifm_media) != IFM_AUTO)
      printf("Media subtype is not AUTO, it is : %d.\n",
             IFM_SUBTYPE(ifm->ifm_media));

   return (0);
}


/*
 *-----------------------------------------------------------------------------
 * vxn_attach --
 *      Initialize data structures and attach driver to stack
 *
 * Results:
 *      Returns 0 for success, negative errno value otherwise.
 *
 * Side effects:
 *      Check device version number. Map interrupts.
 *-----------------------------------------------------------------------------
 */
static int
vxn_attach(device_t dev)
{
   struct ifnet *ifp = NULL;
   int error = 0;
   int s, i;
   vxn_softc_t *sc;
   int unit;
   int rid;
   u_int32_t r;
   u_int32_t vLow, vHigh;
   int driverDataSize;
   u_char mac[6];
   u_int32_t features;
   u_int32_t capabilities;
   u_int32_t maxNumRxBuffers, defNumRxBuffers;
   u_int32_t maxNumTxBuffers, defNumTxBuffers;
   boolean_t enhanced = FALSE;
   u_int32_t if_capabilities = 0;

   s = splimp();

   unit = device_get_unit(dev);

   sc = device_get_softc(dev);
   VXN_MTX_INIT(&sc->vxn_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
                MTX_DEF);
   sc->vxn_io = NULL;
   sc->vxn_irq = NULL;
   sc->vxn_intrhand = NULL;
   sc->vxn_dd = NULL;
   sc->vxn_tx_pending = 0;
   sc->vxn_rings_allocated = 0;
   sc->vxn_max_tx_frags = 1;
   sc->vxn_chain_tx = FALSE;
   sc->vxn_chain_rx = FALSE;
   sc->vxn_zero_copy_tx = FALSE;
   sc->vxn_timer = 0;
   sc->vxn_csum_tx_req_cnt = 0;
   sc->vxn_csum_rx_ok_cnt = 0;

   pci_enable_busmaster(dev);

   /*
    * enable the I/O ports on the device
    */
   pci_enable_io(dev, SYS_RES_IOPORT);
   r = pci_read_config(dev, PCIR_COMMAND, 4);
   if (!(r & PCIM_CMD_PORTEN)) {
      printf("vxn%d: failed to enable I/O ports\n", unit);
      error = ENXIO;
      goto fail;
   }
   rid = VXN_PCIR_MAPS;
   sc->vxn_io = bus_alloc_resource(dev, SYS_RES_IOPORT, &rid, 0, ~0,
                                   1, RF_ACTIVE);
   if (sc->vxn_io == NULL) {
      printf ("vxn%d: couldn't map I/O ports\n", unit);
      error = ENXIO;
      goto fail;
   }
   sc->vxn_iobtag = rman_get_bustag(sc->vxn_io);
   sc->vxn_iobhandle = rman_get_bushandle(sc->vxn_io);

   /*
    * check the version number of the device implementation
    */
   vLow = bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_LOW_VERSION);
   vHigh = bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_HIGH_VERSION);
   if ((vLow & 0xffff0000) != (VMXNET2_MAGIC & 0xffff0000)) {
      printf("vxn%d: driver version 0x%08X doesn't match %s version 0x%08X\n",
             unit, VMXNET2_MAGIC, "VMware", rid);
      error = ENXIO;
      goto fail;
   } else {
      if ((VMXNET2_MAGIC < vLow) ||
          (VMXNET2_MAGIC > vHigh)) {
         printf("vxn%d: driver version 0x%08X doesn't match %s version 0x%08X,0x%08X\n",
                unit, VMXNET2_MAGIC, "VMware", vLow, vHigh);
         error = ENXIO;
         goto fail;
      }
   }

   /*
    * map interrupt for the the device
    */
   rid = 0;
   sc->vxn_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid, 0, ~0,
                                    1, RF_SHAREABLE | RF_ACTIVE);
   if (sc->vxn_irq == NULL) {
      printf("vxn%d: couldn't map interrupt\n", unit);
      error = ENXIO;
      goto fail;
   }
#if defined(VXN_NEWNEWBUS)
   error = bus_setup_intr(dev, sc->vxn_irq, INTR_TYPE_NET | INTR_MPSAFE,
                          NULL, vxn_intr, sc, &sc->vxn_intrhand);
#elif defined(VXN_MPSAFE)
   error = bus_setup_intr(dev, sc->vxn_irq, INTR_TYPE_NET | INTR_MPSAFE,
			  vxn_intr, sc, &sc->vxn_intrhand);
#else 
   error = bus_setup_intr(dev, sc->vxn_irq, INTR_TYPE_NET,
			  vxn_intr, sc, &sc->vxn_intrhand);
#endif
   if (error) {
      printf("vxn%d: couldn't set up irq\n", unit);
      error = ENXIO;
      goto fail;
   }

   capabilities = vxn_execute_4(sc, VMXNET_CMD_GET_CAPABILITIES);
   features = vxn_execute_4(sc, VMXNET_CMD_GET_FEATURES);
   sc->vxn_capabilities = capabilities;
   sc->vxn_features = features;

#ifdef CO_DO_ZERO_COPY
   if( capabilities & VMNET_CAP_SG &&
       features & VMXNET_FEATURE_ZERO_COPY_TX ) {
      sc->vxn_zero_copy_tx = TRUE;

      if (capabilities & VMNET_CAP_TX_CHAIN) {
         sc->vxn_chain_tx = TRUE;
      }

      if (capabilities & VMNET_CAP_RX_CHAIN) {
         sc->vxn_chain_rx = TRUE;
      }

      if( sc->vxn_chain_tx && sc->vxn_chain_rx
       && (features & VMXNET_FEATURE_JUMBO_FRAME) ) {
         if_capabilities |= IFCAP_JUMBO_MTU;
      }
   }

#ifdef CO_DO_TSO
   if ((capabilities & VMNET_CAP_TSO) &&
     (capabilities & (VMNET_CAP_IP4_CSUM | VMNET_CAP_HW_CSUM)) &&
     // tso only makes sense if we have hw csum offload
     sc->vxn_chain_tx && sc->vxn_zero_copy_tx
     && (features & VMXNET_FEATURE_TSO) ) {
      if_capabilities |= IFCAP_TSO4;
   }
   if ((capabilities & VMNET_CAP_TSO6) &&
     (capabilities & (VMNET_CAP_IP6_CSUM | VMNET_CAP_HW_CSUM)) &&
     // tso only makes sense if we have hw csum offload
     sc->vxn_chain_tx && sc->vxn_zero_copy_tx
     && (features & VMXNET_FEATURE_TSO) ) {
      if_capabilities |= IFCAP_TSO6;
   }
#endif
#endif

   if( capabilities & VMNET_CAP_IP4_CSUM) {
      if_capabilities |= IFCAP_HWCSUM;
   }
   if( capabilities & VMNET_CAP_HW_CSUM) {
      if_capabilities |= IFCAP_HWCSUM;
   }

   if( (features & VMXNET_FEATURE_TSO)
    && (features & VMXNET_FEATURE_JUMBO_FRAME) ) {
      enhanced = TRUE;
   }

   if( enhanced ) {
      maxNumRxBuffers = ENHANCED_VMXNET2_MAX_NUM_RX_BUFFERS;
      defNumRxBuffers = ENHANCED_VMXNET2_DEFAULT_NUM_RX_BUFFERS;
   }
   else {
      maxNumRxBuffers = VMXNET2_MAX_NUM_RX_BUFFERS;
      defNumRxBuffers = VMXNET2_DEFAULT_NUM_RX_BUFFERS;
   }

   if( if_capabilities & IFCAP_JUMBO_MTU ) {
      maxNumTxBuffers = VMXNET2_MAX_NUM_TX_BUFFERS_TSO;
      defNumTxBuffers = VMXNET2_DEFAULT_NUM_TX_BUFFERS_TSO;
   }
   else {
      maxNumTxBuffers = VMXNET2_MAX_NUM_TX_BUFFERS;
      defNumTxBuffers = VMXNET2_DEFAULT_NUM_TX_BUFFERS;
   }


   /*
    * allocate and initialize our private and shared data structures
    */
   r = vxn_execute_4(sc, VMXNET_CMD_GET_NUM_RX_BUFFERS);
   if (r == 0 || r > maxNumRxBuffers) {
      r = defNumRxBuffers;
   }
   sc->vxn_num_rx_max_bufs = r;

   if( if_capabilities & IFCAP_JUMBO_MTU ) {
      r = sc->vxn_num_rx_max_bufs * 4;
      if( r > VMXNET2_MAX_NUM_RX_BUFFERS2 ) {
         r = VMXNET2_MAX_NUM_RX_BUFFERS2;
      }
   } else {
      r = 1;
   }
   sc->vxn_num_rx_max_bufs2 = r;

   r = vxn_execute_4(sc, VMXNET_CMD_GET_NUM_TX_BUFFERS);
   if (r == 0 || r > maxNumTxBuffers ) {
      r = defNumTxBuffers;
   }
   sc->vxn_num_tx_max_bufs = r;

   driverDataSize =
      sizeof(Vmxnet2_DriverData) +
      /* numRxBuffers + 1 for the dummy rxRing2 (used only by Windows) */
      (sc->vxn_num_rx_max_bufs + sc->vxn_num_rx_max_bufs2) * sizeof(Vmxnet2_RxRingEntry) +
      sc->vxn_num_tx_max_bufs * sizeof(Vmxnet2_TxRingEntry);

   sc->vxn_dd = contigmalloc(driverDataSize, M_DEVBUF, M_NOWAIT,
                             0, 0xffffffff, PAGE_SIZE, 0);
   if (sc->vxn_dd == NULL) {
      printf("vxn%d: can't contigmalloc %d bytes for vxn_dd\n",
             unit, driverDataSize);
      error = ENOMEM;
      goto fail;
   }

   memset(sc->vxn_dd, 0, driverDataSize);

   /* So that the vmkernel can check it is compatible */
   sc->vxn_dd->magic = VMXNET2_MAGIC;
   sc->vxn_dd->length = driverDataSize;
   sc->vxn_dd->rxDriverNext = 0;
   sc->vxn_dd->rxDriverNext2 = 0;
   sc->vxn_dd->txDriverCur = sc->vxn_dd->txDriverNext = 0;

   /* This downcast is OK because we've asked for vxn_dd to fit in 32 bits */
   sc->vxn_dd_phys = (uint32)vtophys(sc->vxn_dd);

   /*
    * set up entry points, data and defaults for the kernel
    */
   ifp = VXN_IF_ALLOC(sc);
   if (ifp == NULL) {
      printf("vxn%d: if_alloc() failed\n", unit);
      error = ENOMEM;
      goto fail;
   }
   ifp->if_softc = sc;
   VXN_IF_INITNAME(ifp, device_get_name(dev), unit);
   ifp->if_mtu = ETHERMTU;
   ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
   ifp->if_ioctl = vxn_ioctl;
   ifp->if_output = ether_output;
   ifp->if_start = vxn_start;
//#if __FreeBSD_version < 900000
//	ifp->if_watchdog = vxn_watchdog;
//#endif
   ifp->if_init = vxn_init;
   ifp->if_baudrate = 1000000000;
#ifdef CO_USE_NEW_ALTQ
   IFQ_SET_MAXLEN( &ifp->if_snd, sc->vxn_num_tx_max_bufs );
   ifp->if_snd.ifq_drv_maxlen = sc->vxn_num_tx_max_bufs;
   IFQ_SET_READY( &ifp->if_snd );
#else
   ifp->if_snd.ifq_maxlen = sc->vxn_num_tx_max_bufs;
#endif
   ifp->if_capabilities = if_capabilities;
   ifp->if_capenable = ifp->if_capabilities;
   if( ifp->if_mtu <= ETHERMTU ) {
      ifp->if_capenable &= ~IFCAP_JUMBO_MTU;
   }
   ifp->if_capenable &= ~IFCAP_TXCSUM;		// Hardware bug? Generated checksum is bad.
   if( ifp->if_capenable & IFCAP_TXCSUM ) {
      ifp->if_hwassist = VMXNET_CSUM_FEATURES;
   } else {
      ifp->if_hwassist = 0;
   }

   /*
    * read the MAC address from the device
    */
   for (i = 0; i < 6; i++) {
      mac[i] = bus_space_read_1(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_MAC_ADDR
                                + i);
   }

#ifdef VXN_NEEDARPCOM
   /*
    * FreeBSD 4.x requires that we manually record the device's MAC address to
    * the attached arpcom structure prior to calling ether_ifattach().
    */
   bcopy(mac, sc->arpcom.ac_enaddr, 6);
#endif

   SYSCTL_ADD_UINT(device_get_sysctl_ctx(dev),
       SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
       OID_AUTO, "csum_tx_req", CTLFLAG_RD, &sc->vxn_csum_tx_req_cnt, 0, "Checksum offload TX count" );
   SYSCTL_ADD_UINT( device_get_sysctl_ctx(dev),
       SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
       OID_AUTO, "csum_rx_ok", CTLFLAG_RD, &sc->vxn_csum_rx_ok_cnt, 0, "Checksum offload RX ok count" );
   SYSCTL_ADD_UINT( device_get_sysctl_ctx(dev),
       SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
       OID_AUTO, "capabilities", CTLFLAG_RD, &sc->vxn_capabilities, 0, "HW capabilities" );
   SYSCTL_ADD_UINT( device_get_sysctl_ctx(dev),
       SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
       OID_AUTO, "features", CTLFLAG_RD, &sc->vxn_features, 0, "HW features" );

   /*
    * success
    */
   VXN_ETHER_IFATTACH(ifp, mac);
   printf("vxn%d: attached [num_rx_bufs=((%d+%u)*%d) num_tx_bufs=(%d*%d) driverDataSize=%d]\n",
          unit,
          sc->vxn_num_rx_max_bufs, sc->vxn_num_rx_max_bufs2, (int)sizeof(Vmxnet2_RxRingEntry),
          sc->vxn_num_tx_max_bufs, (int)sizeof(Vmxnet2_TxRingEntry),
          driverDataSize);

#ifdef CO_USE_TICK
   callout_init_mtx( &sc->vxn_stat_ch, &sc->vxn_mtx, 0 );
#endif
   vxn_link_check( sc );

   /*
    * Specify the media types supported by this adapter and register
    * callbacks to update media and link information
    */
   ifmedia_init(&sc->media, IFM_IMASK, vxn_media_change,
                vxn_media_status);
   ifmedia_add(&sc->media, IFM_ETHER | IFM_FDX, 0, NULL);
   ifmedia_add(&sc->media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
   ifmedia_add(&sc->media, IFM_ETHER | IFM_1000_T, 0, NULL);
   ifmedia_add(&sc->media, IFM_ETHER | IFM_AUTO, 0, NULL);
   ifmedia_set(&sc->media, IFM_ETHER | IFM_AUTO);


   goto done;

fail:

   if (sc->vxn_intrhand != NULL) {
      bus_teardown_intr(dev, sc->vxn_irq, sc->vxn_intrhand);
   }
   if (sc->vxn_irq != NULL) {
      bus_release_resource(dev, SYS_RES_IRQ, 0, sc->vxn_irq);
   }
   if (sc->vxn_io != NULL) {
      bus_release_resource(dev, SYS_RES_IOPORT, VXN_PCIR_MAPS, sc->vxn_io);
   }
   if (sc->vxn_dd != NULL) {
      contigfree(sc->vxn_dd, sc->vxn_dd->length, M_DEVBUF);
   }
   if (ifp != NULL) {
      VXN_IF_FREE(sc);
   }

   pci_disable_io(dev, SYS_RES_IOPORT);
   pci_disable_busmaster(dev);
   VXN_MTX_DESTROY(&sc->vxn_mtx);

  done:

   splx(s);
   return error;
}

/*
 *-----------------------------------------------------------------------------
 * vxn_detach --
 *      Free data structures and detach driver from stack
 *
 * Results:
 *      Returns 0 for success (always)
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static int
vxn_detach(device_t dev)
{
   int s;
   vxn_softc_t *sc;
   struct ifnet *ifp;

   s = splimp();

   sc = device_get_softc(dev);

   ifp = VXN_SC2IFP(sc);

#ifdef CO_USE_TICK
   callout_drain( &sc->vxn_stat_ch );
#endif

   if (device_is_attached(dev)) {
      vxn_stop(sc);
      /*
       * detach from stack
       */
      VXN_ETHER_IFDETACH(ifp);
   }

   /*
    * Cleanup - release resources and memory
    */
   VXN_IF_FREE(sc);
   contigfree(sc->vxn_dd, sc->vxn_dd->length, M_DEVBUF);
   bus_teardown_intr(dev, sc->vxn_irq, sc->vxn_intrhand);
   bus_release_resource(dev, SYS_RES_IRQ, 0, sc->vxn_irq);
   bus_release_resource(dev, SYS_RES_IOPORT, VXN_PCIR_MAPS, sc->vxn_io);
   pci_disable_io(dev, SYS_RES_IOPORT);
   pci_disable_busmaster(dev);
   VXN_MTX_DESTROY(&sc->vxn_mtx);

   splx(s);
   return 0;
}

/*
 *-----------------------------------------------------------------------------
 * vxn_stop --
 *      Called when the interface is brought down
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None
 *
 *-----------------------------------------------------------------------------
 */
static void
vxn_stop(vxn_softc_t *sc)
{
   VXN_LOCK(sc);
   vxn_stopl(sc);
   VXN_UNLOCK(sc);
}

/*
 *-----------------------------------------------------------------------------
 * vxn_stopl --
 *      Called when the interface is brought down & is locked
 *
 * Results:
 *      None
 *
 * Side effects:
 *	Don't do anything if not running. Flush pending transmits. Release
 *      private data structures.
 *-----------------------------------------------------------------------------
 */
static void
vxn_stopl(vxn_softc_t *sc)
{
   int i;
   struct ifnet *ifp = VXN_SC2IFP(sc);

   VXN_LOCK_ASSERT(sc);

   if (!(VXN_GET_IF_DRV_FLAGS(ifp) & VXN_IFF_RUNNING)) {
      return;
   }

#ifdef CO_USE_TICK
   callout_stop(&sc->vxn_stat_ch);
#endif

   /*
    * Disable device interrupts
    */
   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
		     VMXNET_COMMAND_ADDR, VMXNET_CMD_INTR_DISABLE);

   /*
    * Try to flush pending transmits
    */
   if (sc->vxn_tx_pending) {
      if_printf( ifp, "waiting for %d pending transmits\n",
             sc->vxn_tx_pending);
      for (i = 0; i < MAX_TX_WAIT_ON_STOP && sc->vxn_tx_pending; i++) {
         DELAY(1000);
         bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                           VMXNET_COMMAND_ADDR, VMXNET_CMD_CHECK_TX_DONE);
         vxn_tx_complete(sc);
      }
      if (sc->vxn_tx_pending) {
         if_printf( ifp, "giving up on %d pending transmits\n",
            	 sc->vxn_tx_pending);
      }
   }

   /*
    * Stop hardware
    */
   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                     VMXNET_INIT_ADDR, 0);

   VXN_CLR_IF_DRV_FLAGS(ifp, VXN_IFF_RUNNING);

   /*
    * Free ring
    */
   vxn_release_rings(sc);
}

/*
 *-----------------------------------------------------------------------------
 * vxn_load_multicast --
 *      Called to change set of addresses to listen to.
 *
 * Results:
 *      None
 *
 * Side effects:
 *	Sets device multicast table
 *-----------------------------------------------------------------------------
 */
static int
vxn_load_multicast(vxn_softc_t *sc)
{
   struct ifmultiaddr *ifma;
   struct ifnet *ifp = VXN_SC2IFP(sc);
   Vmxnet2_DriverData *dd = sc->vxn_dd;
   volatile uint16 *mcast_table = (uint16 *)dd->LADRF;
   int i, bit, byte;
   uint32 crc, poly = CRC_POLYNOMIAL_LE;
   int any = 0;

   if (ifp->if_flags & IFF_ALLMULTI) {
        dd->LADRF[0] = 0xffffffff;
        dd->LADRF[1] = 0xffffffff;

        any++;
	goto done;
   }

   dd->LADRF[0] = 0;
   dd->LADRF[1] = 0;

   VXN_IF_ADDR_LOCK(ifp);
   for (ifma = VXN_IFMULTI_FIRST(&ifp->if_multiaddrs);
        ifma != NULL;
        ifma = VXN_IFMULTI_NEXT(ifma, ifma_link)) {
      char *addrs = LLADDR((struct sockaddr_dl *)ifma->ifma_addr);

      if (ifma->ifma_addr->sa_family != AF_LINK)
         continue;

      any++;
      crc = 0xffffffff;
      for (byte = 0; byte < 6; byte++) {
         for (bit = *addrs++, i = 0; i < 8; i++, bit >>= 1) {
            int test;

            test = ((bit ^ crc) & 0x01);
            crc >>= 1;

            if (test) {
               crc = crc ^ poly;
            }
         }
      }

      crc = crc >> 26;
      mcast_table[crc >> 4] |= 1 << (crc & 0xf);
   }
   VXN_IF_ADDR_UNLOCK(ifp);

 done:
   if (VXN_GET_IF_DRV_FLAGS(ifp) & VXN_IFF_RUNNING) {
      bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                        VMXNET_COMMAND_ADDR, VMXNET_CMD_UPDATE_LADRF);
   }
   return any;
}

/*
 *-----------------------------------------------------------------------------
 * vxn_init --
 *      Called when the interface is brought up.
 *
 * Results:
 *      None
 *
 * Side effects:
 *
 *-----------------------------------------------------------------------------
 */
static void
vxn_init(void *v)
{
   vxn_softc_t *sc = (vxn_softc_t *)v;
   VXN_LOCK(sc);
   vxn_initl(sc);
   VXN_UNLOCK(sc);
}

/*
 *-----------------------------------------------------------------------------
 * vxn_initl --
 *      Called by vxn_init() after lock acquired.
 *
 * Results:
 *      None
 *
 * Side effects:
 *	Initialize rings, Register driver data structures with device,
 *      Enable interrupts on device.
 *
 *-----------------------------------------------------------------------------
 */
static void
vxn_initl(vxn_softc_t *sc)
{
   Vmxnet2_DriverData *dd = sc->vxn_dd;
   struct ifnet *ifp = VXN_SC2IFP(sc);
   uint32 r, i;
   u_char mac_addr[6];

   VXN_LOCK_ASSERT(sc);

   if (!(VXN_GET_IF_DRV_FLAGS(ifp) & VXN_IFF_RUNNING)) {
      u_int32_t capabilities;
      u_int32_t features;

      if (vxn_init_rings(sc) != 0) {
         if_printf( ifp, "ring intitialization failed\n" );
         return;
      }

      /* Get MAC address from interface and set it in hardware */
#if __FreeBSD_version >= 700000
      printf("addrlen : %d. \n", ifp->if_addrlen);
      bcopy(LLADDR((struct sockaddr_dl *)ifp->if_addr->ifa_addr), mac_addr,
            ifp->if_addrlen > 6 ? 6 : ifp->if_addrlen);
#else
      if (!ifaddr_byindex(ifp->if_index)) {
         printf("vxn:%d Invalid link address, interface index :%d.\n",
                VXN_IF_UNIT(ifp), ifp->if_index);
      } else {
         bcopy(LLADDR((struct sockaddr_dl *)ifaddr_byindex(ifp->if_index)->ifa_addr),
               mac_addr, ifp->if_addrlen);
      }
#endif
      printf("vxn%d: MAC Address : %02x:%02x:%02x:%02x:%02x:%02x \n",
             VXN_IF_UNIT(ifp), mac_addr[0], mac_addr[1], mac_addr[2],
             mac_addr[3], mac_addr[4], mac_addr[5]);
      for (i = 0; i < 6; i++) {
         bus_space_write_1(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_MAC_ADDR +
                           i, mac_addr[i]);
      }

      /*
       * Start hardware
       */
      bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                        VMXNET_INIT_ADDR, sc->vxn_dd_phys);
      bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                        VMXNET_INIT_LENGTH, sc->vxn_dd->length);

      /* Make sure the initialization succeeded for the hardware. */
      r = bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_INIT_LENGTH);
      if (!r) {
         vxn_release_rings(sc);
         if_printf( ifp, "device intitialization failed: %x\n", r );
         return;
      }
      capabilities = vxn_execute_4(sc, VMXNET_CMD_GET_CAPABILITIES);
      features = vxn_execute_4(sc, VMXNET_CMD_GET_FEATURES);
      if ((capabilities & VMNET_CAP_SG) &&
          (features & VMXNET_FEATURE_ZERO_COPY_TX)) {
         sc->vxn_max_tx_frags = VMXNET2_SG_DEFAULT_LENGTH;
      } else {
         sc->vxn_max_tx_frags = 1;
      }

      VXN_SET_IF_DRV_FLAGS(ifp, VXN_IFF_RUNNING);
      VXN_CLR_IF_DRV_FLAGS(ifp, VXN_IFF_OACTIVE);
   }

   dd->ifflags &= ~(VMXNET_IFF_PROMISC
                    |VMXNET_IFF_BROADCAST
                    |VMXNET_IFF_MULTICAST);

   if (ifp->if_flags & IFF_PROMISC) {
      if_printf( ifp, "promiscuous mode enabled\n" );
      dd->ifflags |= VMXNET_IFF_PROMISC;
   }
   if (ifp->if_flags & IFF_BROADCAST) {
      dd->ifflags |= VMXNET_IFF_BROADCAST;
   }
   /*
    * vnx_load_multicast does the right thing for IFF_ALLMULTI
    */
   if (vxn_load_multicast(sc)) {
      dd->ifflags |= VMXNET_IFF_MULTICAST;
   }

   /*
    * enable interrupts on the card
    */
   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                     VMXNET_COMMAND_ADDR, VMXNET_CMD_INTR_ENABLE);

   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
		     VMXNET_COMMAND_ADDR, VMXNET_CMD_UPDATE_IFF);

#ifdef CO_USE_TICK
   callout_reset( &sc->vxn_stat_ch, hz, vxn_tick, sc );
#endif
}

static void
vxn_link_check( vxn_softc_t *sc )
{
   struct ifnet *ifp = VXN_SC2IFP(sc);
   uint32 stat;
   int ok;
   int link;

   stat = bus_space_read_4( sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_STATUS_ADDR );
   ok = ((stat & VMXNET_STATUS_CONNECTED) != 0);
   link = ((ifp->if_link_state & LINK_STATE_UP) != 0);

   if( !ok ) {
      if( link ) {
         if_link_state_change( ifp, LINK_STATE_DOWN );
      }
   } else {
      if( !link ) {
         if_link_state_change( ifp, LINK_STATE_UP );
      }
   }
}

/*
 *-----------------------------------------------------------------------------
 * vxn_encap --
 *     Stick packet address and length in given ring entry
 *     パケットアドレスと長さを(送信)リングエントリに組む
 *
 * Results:
 *      0 on success, 1 on error
 *
 * Side effects:
 *	Allocate a new mbuf cluster and copy data, if mbuf chain is too
 *	fragmented for us to include in our scatter/gather array
 *
 *-----------------------------------------------------------------------------
 */
static int
vxn_encap(struct ifnet *ifp,
	  Vmxnet2_TxRingEntry *xre,
	  struct mbuf *m_head,
	  struct mbuf **pbuffptr)
{
   vxn_softc_t *sc = ifp->if_softc;
   int frag = 0;
   struct mbuf *m;
   vm_paddr_t sc_addr;

   xre->sg.length = 0;
   xre->flags = 0;

   /*
    * Go through mbuf chain and drop packet pointers into ring
    * scatter/gather array
    */
   for (m = m_head; m != NULL; m = m->m_next) {
      if (m->m_len) {
         if (frag == sc->vxn_max_tx_frags) {
            break;
         }

         sc_addr = vtophys(mtod(m, vm_offset_t));
         xre->sg.sg[frag].addrLow = (uint32)(sc_addr & 0xFFFFFFFF);
         xre->sg.sg[frag].addrHi = (uint16)(sc_addr >> 32);
         xre->sg.sg[frag].length = m->m_len;
         frag++;
      }
   }

   /*
    * Allocate a new mbuf cluster and copy data if we can't use the mbuf chain
    * as such
    */
   if (m != NULL) {
      struct mbuf    *m_new = NULL;

      MGETHDR(m_new, M_DONTWAIT, MT_DATA);
      if (m_new == NULL) {
         if_printf( ifp, "no memory for tx list\n" );
         return 1;
      }

      if (m_head->m_pkthdr.len > MHLEN) {
         if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
            m_cljget(m_new, M_NOWAIT, MJUM9BYTES);
         } else {
            MCLGET(m_new, M_NOWAIT);
         }
         if (!(m_new->m_flags & M_EXT)) {
            m_freem(m_new);
            if_printf( ifp, "no memory for tx list\n" );
            return 1;
         }
      }

      m_copydata(m_head, 0, m_head->m_pkthdr.len,
          mtod(m_new, caddr_t));
      m_new->m_pkthdr.len = m_new->m_len = m_head->m_pkthdr.len;
#ifdef CO_USE_NEW_ALTQ
      IFQ_DEQUEUE_NOLOCK( &ifp->if_snd, m_head );
#endif
      m_freem(m_head);
      m_head = m_new;

      sc_addr = vtophys(mtod(m_head, vm_offset_t));
      xre->sg.sg[0].addrLow = (uint32)(sc_addr & 0xFFFFFFFF);
      xre->sg.sg[0].addrHi = (uint16)(sc_addr >> 32);
      xre->sg.sg[0].length = m_head->m_pkthdr.len;
      frag = 1;
   }
#ifdef CO_USE_NEW_ALTQ
   else {
      IFQ_DEQUEUE_NOLOCK( &ifp->if_snd, m_head );
   }
#endif

   xre->sg.length = frag;

   /*
    * Mark ring entry as "NIC owned"
    */
   if (frag > 0) {
      if( ifp->if_capenable & IFCAP_TXCSUM ) {
         if (m_head->m_pkthdr.csum_flags & (CSUM_TCP | CSUM_UDP)) {
            xre->flags |= VMXNET2_TX_HW_XSUM;
            sc->vxn_csum_tx_req_cnt++;
         }
      }
      xre->sg.addrType = NET_SG_PHYS_ADDR;
      *pbuffptr = m_head;
      xre->ownership = VMXNET2_OWNERSHIP_NIC;
      xre->flags |= VMXNET2_TX_CAN_KEEP;
   }

   return 0;
}

/*
 *-----------------------------------------------------------------------------
 * vxn_start --
 *     Called to transmit a packet.  Acquires device mutex & hands off to
 *     vxn_startl.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None
 *
 *-----------------------------------------------------------------------------
 */

static void
vxn_start(struct ifnet *ifp)
{
   VXN_LOCK((vxn_softc_t *)ifp->if_softc);
   vxn_startl(ifp);
   VXN_UNLOCK((vxn_softc_t *)ifp->if_softc);
}

#ifdef CO_DO_TSO
static int
vxn_get_hdrlen( struct ifnet *ifp, struct mbuf *m )
{
   u_int32_t hdr_len = 0;

   struct ether_header hdr_eth;
   struct ip hdr_ip;
   struct ip6_hdr hdr_ip6;
   struct tcphdr hdr_tcp;

   hdr_len += ETHER_HDR_LEN;
   if( m->m_pkthdr.len < hdr_len ) {
      return 0;
   }

   m_copydata( m, 0, sizeof(struct ether_header), (caddr_t)(&hdr_eth) );
   if( (hdr_eth.ether_type & ETHERTYPE_IP)
    && (ifp->if_capenable & IFCAP_TSO4) ) {
      if( m->m_pkthdr.len < (hdr_len + sizeof(struct ip)) ) {
         return hdr_len;
      }

      m_copydata( m, hdr_len, sizeof(struct ip), (caddr_t)(&hdr_ip) );
      hdr_len += hdr_ip.ip_hl << 2;
      if( hdr_ip.ip_p != IPPROTO_TCP ) { // exclude TCP
         return hdr_len;
      }

      if( m->m_pkthdr.len < (hdr_len + sizeof(struct tcphdr)) ) {
         return hdr_len;
      }

      m_copydata( m, hdr_len, sizeof(struct tcphdr), (caddr_t)(&hdr_tcp) );
      hdr_len += hdr_tcp.th_off << 2;
   } else
   if( (hdr_eth.ether_type & ETHERTYPE_IPV6)
    && (ifp->if_capenable & IFCAP_TSO6) ) {
      if( m->m_pkthdr.len < (hdr_len + sizeof(struct ip6_hdr)) ) {
         return hdr_len;
      }

      m_copydata( m, hdr_len, sizeof(struct ip6_hdr), (caddr_t)(&hdr_ip6) );
      hdr_len = m->m_pkthdr.len - hdr_ip6.ip6_plen;
      if( hdr_ip6.ip6_nxt != IPPROTO_TCP ) { // exclude TCP
         return hdr_len;
      }

      m_copydata( m, hdr_len, sizeof(struct tcphdr), (caddr_t)(&hdr_tcp) );
      hdr_len += hdr_tcp.th_off << 2;
   }

   return hdr_len;
}
#endif

/*
 *-----------------------------------------------------------------------------
 * vxn_startl --
 *     Called to transmit a packet (lock acquired)
 *
 * Results:
 *      None
 *
 * Side effects:
 *	Bounces a copy to possible BPF listener. Sets RING_LOW flag
 *	if ring is getting crowded. Starts device TX. Aggressively cleans
 *	up tx ring after starting TX.
 *
 *-----------------------------------------------------------------------------
 */
static void
vxn_startl(struct ifnet *ifp)
{
   vxn_softc_t *sc = ifp->if_softc;
   Vmxnet2_DriverData *dd = sc->vxn_dd;
#ifdef CO_DO_TSO
   int hdrlen = 0;
   int pktlen = 0;
   int mss = 0;
#endif

   VXN_LOCK_ASSERT(sc);

   if (VXN_GET_IF_DRV_FLAGS(ifp) & VXN_IFF_OACTIVE) {
      return;
   }

   /*
    * No room on ring
    */
   if (sc->vxn_tx_buffptr[dd->txDriverNext]) {
      dd->txStopped = TRUE;
   }

#ifdef CO_USE_NEW_ALTQ
   IFQ_LOCK( &ifp->if_snd );
#endif

   /*
    * Dequeue packets from send queue and drop them into tx ring
    */
   while (sc->vxn_tx_buffptr[dd->txDriverNext] == NULL) {
      struct mbuf *m_head = NULL;
      Vmxnet2_TxRingEntry *xre;

#ifdef CO_USE_NEW_ALTQ
      IFQ_POLL_NOLOCK( &ifp->if_snd, m_head );
#else
      IF_DEQUEUE( &ifp->if_snd, m_head );
#endif
      if (m_head == NULL) {
         break;
      }

#ifdef CO_DO_TSO
      if( ifp->if_capenable & IFCAP_TSO ) {
         mss = m_head->m_pkthdr.tso_segsz;
         if( mss ) {
            pktlen = m_head->m_pkthdr.len;
            hdrlen = vxn_get_hdrlen( ifp, m_head );
         }
      }
#endif

      xre = &sc->vxn_tx_ring[dd->txDriverNext];
      if (vxn_encap(ifp, xre, m_head, &(sc->vxn_tx_buffptr[dd->txDriverNext]))) {
#ifndef CO_USE_NEW_ALTQ
         IF_PREPEND(&ifp->if_snd, m_head);
#endif
         break;
      }

      /*
       * Bounce copy to (possible) BPF listener
       */
      VXN_BPF_MTAP(ifp, sc->vxn_tx_buffptr[dd->txDriverNext]);

      if (sc->vxn_tx_pending > (dd->txRingLength - 5)) {
         xre->flags |= VMXNET2_TX_RING_LOW;
      }

#ifdef CO_DO_TSO
      if( (ifp->if_capenable & IFCAP_TSO) && mss && pktlen ) {
         dd->txNumDeferred += ((pktlen - hdrlen) + mss - 1) / mss;
         xre->flags |= VMXNET2_TX_TSO;
         xre->tsoMss = mss;
      } else
#endif
      {
         dd->txNumDeferred++;
      }

      ifp->if_obytes += m_head->m_pkthdr.len;
      ifp->if_opackets++;
      VMXNET_INC(dd->txDriverNext, dd->txRingLength);
      sc->vxn_tx_pending++;
   }

#ifdef CO_USE_NEW_ALTQ
   IFQ_UNLOCK( &ifp->if_snd );
#endif

   /*
    * Transmit, if number of pending packets > tx cluster length
    */
   if (dd->txNumDeferred >= dd->txClusterLength) {
      dd->txNumDeferred = 0;

      /*
       * reading this port causes the implementation to transmit everything
       * in the ring
       */
      bus_space_read_4(sc->vxn_iobtag, sc->vxn_iobhandle, VMXNET_TX_ADDR);
   }

   sc->vxn_timer = 5;

   /*
    * Clean up tx ring after calling into vmkernel, as TX completion intrs
    * are not guaranteed.
    */
   vxn_tx_complete(sc);
}

/*
 *-----------------------------------------------------------------------------
 * vxn_ioctl --
 *     IOCTL
 *
 * Results:
 *      Returns 0 for success, negative errno value otherwise.
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static int
vxn_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
   int error = 0;
   int s;
   vxn_softc_t *sc = ifp->if_softc;
   struct ifreq *ifr = (struct ifreq *)data;

   s = splimp();

   switch(command) {
   case SIOCSIFADDR:
   case SIOCGIFADDR:
      error = ether_ioctl(ifp, command, data);
      break;

   case SIOCSIFMTU:
      VXN_LOCK(sc);
      if ((ifr->ifr_mtu < VMXNET_MIN_MTU) || (ifr->ifr_mtu > VMXNET_MAX_MTU)) {
         error = EINVAL;
      }
      else if (ifr->ifr_mtu > 1500 && !(ifp->if_capabilities & IFCAP_JUMBO_MTU) ) {
         error = EINVAL;
      }
      else {
         if( (ifp->if_mtu <= 1500) && (ifr->ifr_mtu > 1500) ) {
            // not jumbo to jumbo
            vxn_stopl(sc);
            ifp->if_capenable |= IFCAP_JUMBO_MTU;
            ifp->if_mtu = ifr->ifr_mtu;
            vxn_initl(sc);
         } else
         if( (ifp->if_mtu > 1500) && (ifr->ifr_mtu <= 1500) ) {
            // jumbo to not jumbo
            vxn_stopl(sc);
            ifp->if_capenable &= ~IFCAP_JUMBO_MTU;
            ifp->if_mtu = ifr->ifr_mtu;
            vxn_initl(sc);
         } else {
            ifp->if_mtu = ifr->ifr_mtu;
         }
         error = 0;
      }
      VXN_UNLOCK(sc);
      break;
   case SIOCSIFFLAGS:
      VXN_LOCK(sc);
      if (ifp->if_flags & IFF_UP) {
         vxn_initl(sc);
      } else {
         vxn_stopl(sc);
      }
      if( ifp->if_flags & IFF_PROMISC ) {
         sc->vxn_dd->ifflags |= VMXNET_IFF_PROMISC;
      } else {
         sc->vxn_dd->ifflags &= ~VMXNET_IFF_PROMISC;
      }
      VXN_UNLOCK(sc);
      break;

   case SIOCADDMULTI:
   case SIOCDELMULTI:
      VXN_LOCK(sc);
      vxn_load_multicast(sc);
      VXN_UNLOCK(sc);
      error = 0;
      break;

   case SIOCSIFCAP:
      {
         int mask = ifr->ifr_reqcap ^ ifp->if_capenable;
         if( mask & IFCAP_TXCSUM ) {
            ifp->if_capenable ^= IFCAP_TXCSUM;
            if( (IFCAP_TXCSUM & ifp->if_capenable)
             && (IFCAP_TXCSUM & ifp->if_capabilities) ) {
            	ifp->if_hwassist = VMXNET_CSUM_FEATURES;
            } else {
            	ifp->if_hwassist = 0;
            }
         }
         if( mask & IFCAP_RXCSUM ) {
            ifp->if_capenable ^= IFCAP_RXCSUM;
         }
         if( mask & IFCAP_TSO4 ) {
            ifp->if_capenable ^= IFCAP_TSO4;
         }
         if( mask & IFCAP_TSO6 ) {
            ifp->if_capenable ^= IFCAP_TSO6;
         }
      }
      break;

   case SIOCSIFMEDIA:
   case SIOCGIFMEDIA:
      ifmedia_ioctl(ifp, (struct ifreq *)data, &sc->media, command);

   default:
      error = EINVAL;
      break;
   }

   splx(s);

   return error;
}

#ifdef CO_USE_TICK
static void
vxn_watchdog(struct ifnet *ifp)
{
   vxn_softc_t *sc = ifp->if_softc;

   VXN_LOCK_ASSERT(sc);

   if( sc->vxn_timer == 0 || --sc->vxn_timer ) {
      return;
   }

   ifp->if_oerrors++;

   if_printf( ifp, "watchdog\n" );
}
#else
#  if __FreeBSD_version < 900000
/*
 *-----------------------------------------------------------------------------
 * vxn_watchdog --
 *	Watchdog function
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Not implemented.
 *-----------------------------------------------------------------------------
 */
static void
vxn_watchdog(struct ifnet *ifp)
{
   if_printf( ifp, "watchdog\n" );
}
#  endif
#endif

#ifdef CO_USE_TICK
static void
vxn_tick(void *xsc)
{
   struct vxn_softc *sc = xsc;

   VXN_LOCK_ASSERT(sc);

    /* Synchronize with possible callout reset/stop. */
   if( callout_pending( &sc->vxn_stat_ch ) ||
      !callout_active( &sc->vxn_stat_ch ) ) {
      return;
   }

   vxn_link_check( sc );

   vxn_watchdog( VXN_SC2IFP(sc) );

   callout_reset( &sc->vxn_stat_ch, hz, vxn_tick, sc );
}
#endif

/*
 *-----------------------------------------------------------------------------
 * vxn_intr --
 *	Interrupt handler
 *
 * Results:
 *	None
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static void
vxn_intr (void *v)
{
   vxn_softc_t *sc = (vxn_softc_t *)v;
   struct ifnet *ifp = VXN_SC2IFP(sc);

   VXN_LOCK(sc);

   /*
    * Without rings being allocated we have nothing to do.  We should not
    * need even this INTR_ACK, as our hardware should be disabled when
    * rings are not allocated, but on other side INTR_ACK should be noop
    * then, and this makes sure that some bug will not force IRQ line
    * active forever.
    */
   bus_space_write_4(sc->vxn_iobtag, sc->vxn_iobhandle,
                     VMXNET_COMMAND_ADDR, VMXNET_CMD_INTR_ACK);

   if (sc->vxn_rings_allocated) {
      vxn_rx(sc);
      vxn_tx_complete(sc);
      /*
       * After having freed some of the transmit ring, go ahead and refill
       * it, if possible, while we're here.  (Idea stolen from if_sis.c.)
       */
      if (!VXN_IFQ_IS_EMPTY(&ifp->if_snd)) {
         vxn_startl(ifp);
      }
   }

   VXN_UNLOCK(sc);
}

#ifdef CO_DO_ZERO_COPY
static void
vxn_drop_frags( vxn_softc_t *sc )
{
   Vmxnet2_DriverData *dd = sc->vxn_dd;
   Vmxnet2_RxRingEntry *rre2;
   uint16 flags;

   do {
      rre2 = &sc->vxn_rx_ring2[dd->rxDriverNext2];
      flags = rre2->flags;

      rre2->ownership = VMXNET2_OWNERSHIP_NIC_FRAG;
      VMXNET_INC(dd->rxDriverNext2, dd->rxRingLength2);
   }  while(!(flags & VMXNET2_RX_FRAG_EOP));
}

static boolean_t
vxn_rx_frags( vxn_softc_t *sc, struct mbuf *m )
{
   Vmxnet2_DriverData *dd = sc->vxn_dd;
   Vmxnet2_RxRingEntry *rre2;
   uint16 flags;
   struct mbuf *m_top = m;

   do {
      rre2 = &sc->vxn_rx_ring2[dd->rxDriverNext2];
      flags = rre2->flags;

      if(rre2->ownership != VMXNET2_OWNERSHIP_DRIVER_FRAG) {
          break;
      }

      if (rre2->actualLength > 0) {
         struct mbuf *m_new = NULL;
         struct mbuf *m2 = sc->vxn_rx_buffptr2[dd->rxDriverNext2];

         /* refill the buffer */
         MGET(m_new, M_DONTWAIT, MT_DATA);
         if (m_new != NULL) {
            MCLGET(m_new, M_DONTWAIT);
            if (!(m_new->m_flags & M_EXT)) {
            	m_freem(m_new);
            	m_new = NULL;
            }
         }
         if (m_new != NULL) {
            m2->m_len = rre2->actualLength;
            m->m_next = m2;
            m2->m_next = NULL;
            m = m2;
            m_top->m_pkthdr.len += rre2->actualLength;

            sc->vxn_rx_buffptr2[dd->rxDriverNext2] = m_new;
            rre2->paddr = (uint64)vtophys(mtod(m_new, caddr_t));
            rre2->bufferLength = MCLBYTES;
            rre2->actualLength = 0;
         } else {
            vxn_drop_frags( sc );
            return FALSE;
         }
      }

      rre2->ownership = VMXNET2_OWNERSHIP_NIC_FRAG;
      VMXNET_INC(dd->rxDriverNext2, dd->rxRingLength2);
   } while (!(flags & VMXNET2_RX_FRAG_EOP));

   return TRUE;
}
#endif

/*
 *-----------------------------------------------------------------------------
 * vxn_rx --
 *	RX handler
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Scan RX ring and pass legit packets up to FreeBSD. Allocate a
 *      new mbuf for each packet pulled out, stick it into the ring and
 *      pass ownership back to NIC.
 *-----------------------------------------------------------------------------
 */
static void
vxn_rx(vxn_softc_t *sc)
{
   short pkt_len;
   struct ifnet *ifp = VXN_SC2IFP(sc);
   Vmxnet2_DriverData *dd = sc->vxn_dd;

   /*
    * receive packets from all the descriptors that the device implementation
    * has given back to us
    */
   while (1) {
      Vmxnet2_RxRingEntry *rre;
      VXN_LOCK_ASSERT(sc);

      rre = &sc->vxn_rx_ring[dd->rxDriverNext];
      if (rre->ownership != VMXNET2_OWNERSHIP_DRIVER) {
         break;
      }

      pkt_len = rre->actualLength;

      if (pkt_len < (60 - 4)) {
#ifdef CO_DO_ZERO_COPY
         if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
            if( rre->flags & VMXNET2_RX_WITH_FRAG) {
            	vxn_drop_frags( sc );
            }
         }
#endif
         ifp->if_ierrors++;

         /*
          * Ethernet header vlan tags are 4 bytes.  Some vendors generate
          *  60byte frames including vlan tags.  When vlan tag
          *  is stripped, such frames become 60 - 4. (PR106153)
          */
         if (pkt_len != 0) {
            if_printf( ifp, "runt packet\n" );
         }
      } else {
         struct mbuf *m_new = NULL;

         /*
	  * Allocate a new mbuf cluster to replace the current one
          */
         MGETHDR(m_new, M_DONTWAIT, MT_DATA);
         if (m_new != NULL) {
            MCLGET(m_new, M_DONTWAIT);
            if (m_new->m_flags & M_EXT) {
               m_adj(m_new, ETHER_ALIGN);
            } else {
               m_freem(m_new);
               m_new = NULL;
            }
         }

         /*
          * replace the current mbuf in the descriptor with the new one
          * and pass the packet up to the kernel
          */
         if (m_new != NULL) {
            struct mbuf *m = sc->vxn_rx_buffptr[dd->rxDriverNext];

            sc->vxn_rx_buffptr[dd->rxDriverNext] = m_new;
            rre->paddr = (uint64)vtophys(mtod(m_new, caddr_t));
            rre->bufferLength = MCLBYTES - ETHER_ALIGN;
            rre->actualLength = 0;

            ifp->if_ipackets++;
            m->m_pkthdr.rcvif = ifp;
            m->m_pkthdr.len = m->m_len = pkt_len;

#ifdef CO_DO_ZERO_COPY
            if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
            	if( rre->flags & VMXNET2_RX_WITH_FRAG) {
            		if( !vxn_rx_frags( sc, m ) ) {
            			ifp->if_ierrors++;
            			continue;
            		}
            	}
            }
#endif

            if( ifp->if_capenable & IFCAP_RXCSUM ) {
            	if (rre->flags & VMXNET2_RX_HW_XSUM_OK) {
            		m->m_pkthdr.csum_flags |= CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
            		m->m_pkthdr.csum_data = 0xffff;
            		sc->vxn_csum_rx_ok_cnt++;
            	}
            }

            ifp->if_ibytes += m->m_pkthdr.len;

            /*
             * "Drop the driver lock around calls to if_input to avoid a LOR
             * when the packets are immediately returned for sending (e.g.  when
             * bridging or packet forwarding).  There are more efficient ways to
             * do this but for now use the least intrusive approach."
             *   - Sam Leffler (sam@FreeBSD.org), if_sis.c rev 1.90
             *
             * This function is only called by the interrupt handler, and said
             * handler isn't reentrant.  (Interrupts are masked.)  I.e., the
             * receive rings are still protected while we give up the mutex.
             */
            VXN_UNLOCK(sc);
            VXN_ETHER_INPUT(ifp, m);
            VXN_LOCK(sc);
         }
         else {
#ifdef CO_DO_ZERO_COPY
            if( ifp->if_capenable & IFCAP_RXCSUM ) {
            	if( rre->flags & VMXNET2_RX_WITH_FRAG) {
            		vxn_drop_frags( sc );
            	}
            }
#endif
            ifp->if_ierrors++;
         }
      }

      /*
       * Give the descriptor back to the device implementation
       */
      rre->ownership = VMXNET2_OWNERSHIP_NIC;
      VMXNET_INC(dd->rxDriverNext, dd->rxRingLength);
   }
}

/*
 *-----------------------------------------------------------------------------
 * vxn_tx_complete --
 *	Loop through the tx ring looking for completed transmits
 *
 * Results:
 *	None
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static void
vxn_tx_complete(vxn_softc_t *sc)
{
   Vmxnet2_DriverData *dd = sc->vxn_dd;

   while (1) {
      Vmxnet2_TxRingEntry *xre = &sc->vxn_tx_ring[dd->txDriverCur];

      if (xre->ownership != VMXNET2_OWNERSHIP_DRIVER ||
	  sc->vxn_tx_buffptr[dd->txDriverCur] == NULL) {
         break;
      }

      m_freem(sc->vxn_tx_buffptr[dd->txDriverCur]);
      sc->vxn_tx_buffptr[dd->txDriverCur] = NULL;
      sc->vxn_tx_pending--;
      VMXNET_INC(dd->txDriverCur, dd->txRingLength);
      dd->txStopped = FALSE;
   }

   if( sc->vxn_tx_pending == 0 ) {
      sc->vxn_timer = 0;
   }
}

/*
 *-----------------------------------------------------------------------------
 * vxn_init_rings --
 *	Loop through the tx ring looking for completed transmits
 *
 * Results:
 *	Returns 0 for success, negative errno value otherwise.
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static int
vxn_init_rings(vxn_softc_t *sc)
{
   Vmxnet2_DriverData *dd = sc->vxn_dd;
   struct ifnet *ifp = VXN_SC2IFP(sc);
   int i;
   int j;
   int32 offset;

   offset = sizeof(*dd);

   sc->vxn_num_rx_bufs = sc->vxn_num_rx_max_bufs;
   sc->vxn_num_rx_bufs2 = sc->vxn_num_rx_max_bufs2;
   sc->vxn_num_tx_bufs = sc->vxn_num_tx_max_bufs;

   dd->rxRingLength = sc->vxn_num_rx_bufs;
   dd->rxRingOffset = offset;
   sc->vxn_rx_ring = (Vmxnet2_RxRingEntry *)((uintptr_t)dd + offset);
   offset += sc->vxn_num_rx_bufs * sizeof(Vmxnet2_RxRingEntry);

   dd->rxRingLength2 = sc->vxn_num_rx_bufs2;
   dd->rxRingOffset2 = offset;
   sc->vxn_rx_ring2 = (Vmxnet2_RxRingEntry *)((uintptr_t)dd + offset);
   offset += sc->vxn_num_rx_bufs2 * sizeof(Vmxnet2_RxRingEntry);

   dd->txRingLength = sc->vxn_num_tx_bufs;
   dd->txRingOffset = offset;
   sc->vxn_tx_ring = (Vmxnet2_TxRingEntry *)((uintptr_t)dd + offset);
   offset += sc->vxn_num_tx_bufs * sizeof(Vmxnet2_TxRingEntry);

   /*
    * Allocate receive buffers
    */
   for (i = 0; i < sc->vxn_num_rx_bufs; i++) {
      struct mbuf *m_new = NULL;

      /*
       * Allocate an mbuf and initialize it to contain a packet header and
       * internal data.
       */
      MGETHDR(m_new, M_DONTWAIT, MT_DATA);
      if (m_new != NULL) {
         /* Allocate and attach an mbuf cluster to mbuf. */
         MCLGET(m_new, M_DONTWAIT);
         if (m_new->m_flags & M_EXT) {
            m_adj(m_new, ETHER_ALIGN);
            sc->vxn_rx_ring[i].paddr = (uint64)vtophys(mtod(m_new, caddr_t));
            sc->vxn_rx_ring[i].bufferLength = MCLBYTES -ETHER_ALIGN;
            sc->vxn_rx_ring[i].actualLength = 0;
            sc->vxn_rx_buffptr[i] = m_new;
            sc->vxn_rx_ring[i].ownership = VMXNET2_OWNERSHIP_NIC;
         } else {
            /*
             * Allocation and attachment of mbuf clusters failed.
             */
            m_freem(m_new);
            m_new = NULL;
            goto err_release_ring;
         }
      } else {
         /* Allocation of mbuf failed. */
         goto err_release_ring;
      }
   }

#ifdef CO_DO_ZERO_COPY
   if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
      dd->maxFrags = 65536 / MCLBYTES +2;
      for (j = 0; j < sc->vxn_num_rx_bufs2; j++) {
         struct mbuf *m_new = NULL;

         /*
          * Allocate an mbuf and initialize it to contain a packet header and
          * internal data.
          */
         MGET(m_new, M_DONTWAIT, MT_DATA);
         if (m_new != NULL) {
            /* Allocate and attach an mbuf cluster to mbuf. */
//				m_cljget(m_new, M_DONTWAIT, MJUM9BYTES);
            MCLGET(m_new, M_DONTWAIT);
            if (m_new->m_flags & M_EXT) {
            	sc->vxn_rx_ring2[j].paddr = (uint64)vtophys(mtod(m_new, caddr_t));
//					sc->vxn_rx_ring2[j].bufferLength = MJUM9BYTES;
            	sc->vxn_rx_ring2[j].bufferLength = MCLBYTES;
            	sc->vxn_rx_ring2[j].actualLength = 0;
            	sc->vxn_rx_buffptr2[j] = m_new;
            	sc->vxn_rx_ring2[j].ownership = VMXNET2_OWNERSHIP_NIC_FRAG;
            } else {
            	/*
            	 * Allocation and attachment of mbuf clusters failed.
            	 */
            	m_freem(m_new);
            	m_new = NULL;
            	goto err_release_ring2;
            }
         } else {
            /* Allocation of mbuf failed. */
            goto err_release_ring2;
         }
      }
   } else {
      for (j = 0; j < sc->vxn_num_rx_bufs2; j++) {
         sc->vxn_rx_ring2[j].paddr = 0;
         sc->vxn_rx_ring2[j].bufferLength = 0;
         sc->vxn_rx_ring2[j].actualLength = 0;
         sc->vxn_rx_buffptr2[j] = 0;
         sc->vxn_rx_ring2[j].ownership = VMXNET2_OWNERSHIP_DRIVER;
      }
   }
#else //!CO_DO_ZERO_COPY
   /* dummy rxRing2 tacked on to the end, with a single unusable entry */
   sc->vxn_rx_ring[i].paddr = 0;
   sc->vxn_rx_ring[i].bufferLength = 0;
   sc->vxn_rx_ring[i].actualLength = 0;
   sc->vxn_rx_buffptr[i] = 0;
   sc->vxn_rx_ring[i].ownership = VMXNET2_OWNERSHIP_DRIVER;
#endif //!CO_DO_ZERO_COPY

   /*
    * Give tx ring ownership to DRIVER
    */
   for (i = 0; i < sc->vxn_num_tx_bufs; i++) {
      sc->vxn_tx_ring[i].ownership = VMXNET2_OWNERSHIP_DRIVER;
      sc->vxn_tx_buffptr[i] = NULL;
      sc->vxn_tx_ring[i].sg.addrType = NET_SG_PHYS_ADDR;
   }

//	dd->savedRxNICNext = dd->savedRxNICNext2 = dd->savedTxNICNext = 0;
   dd->txStopped = FALSE;

   sc->vxn_rings_allocated = 1;
   return 0;
err_release_ring2:
   if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
      for (--j; j >= 0; j--) {
         m_freem(sc->vxn_rx_buffptr2[j]);
         sc->vxn_rx_buffptr2[j] = NULL;
         sc->vxn_rx_ring2[j].paddr = 0;
         sc->vxn_rx_ring2[j].bufferLength = 0;
         sc->vxn_rx_ring2[j].ownership = 0;
      }
   }
err_release_ring:
   /*
    * Clearup already allocated mbufs and attached clusters.
    */
  for (--i; i >= 0; i--) {
     m_freem(sc->vxn_rx_buffptr[i]);
     sc->vxn_rx_buffptr[i] = NULL;
     sc->vxn_rx_ring[i].paddr = 0;
     sc->vxn_rx_ring[i].bufferLength = 0;
     sc->vxn_rx_ring[i].ownership = 0;
  }
  return ENOMEM;

}

/*
 *-----------------------------------------------------------------------------
 * vxn_release_rings --
 *	Free tx and rx ring driverdata
 *
 * Results:
 *	None
 *
 * Side effects:
 *	None
 *-----------------------------------------------------------------------------
 */
static void
vxn_release_rings(vxn_softc_t *sc)
{
   struct ifnet *ifp = VXN_SC2IFP(sc);
   int i;

   sc->vxn_rings_allocated = 0;

   /*
    * Free rx ring packets
    */
   for (i = 0; i < sc->vxn_num_rx_bufs; i++) {
      if (sc->vxn_rx_buffptr[i] != NULL) {
         m_freem(sc->vxn_rx_buffptr[i]);
         sc->vxn_rx_buffptr[i] = NULL;
      }
   }

   /*
    * Free rx ring packets
    */
   if( ifp->if_capenable & IFCAP_JUMBO_MTU ) {
      for (i = 0; i < sc->vxn_num_rx_bufs2; i++) {
         if (sc->vxn_rx_buffptr2[i] != NULL) {
            m_freem(sc->vxn_rx_buffptr2[i]);
            sc->vxn_rx_buffptr2[i] = NULL;
         }
      }
   }

   /*
    * Free tx ring packets
    */
   for (i = 0; i < sc->vxn_num_tx_bufs; i++) {
      if (sc->vxn_tx_buffptr[i] != NULL) {
         m_freem(sc->vxn_tx_buffptr[i]);
         sc->vxn_tx_buffptr[i] = NULL;
      }
   }
}

