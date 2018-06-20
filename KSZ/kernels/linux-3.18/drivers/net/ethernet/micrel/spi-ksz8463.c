/**
 * Microchip KSZ8463 SPI driver
 *
 * Copyright (c) 2015-2017 Microchip Technology Inc.
 * Copyright (c) 2010-2015 Micrel, Inc.
 *
 * Copyright 2009 Simtec Electronics
 *	http://www.simtec.co.uk/
 *	Ben Dooks <ben@simtec.co.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if 0
#define DEBUG
#define DBG
#endif

#ifndef CONFIG_KSZ_SWITCH_EMBEDDED
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/cache.h>
#include <linux/crc32.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#endif

/* -------------------------------------------------------------------------- */

#include <linux/net_tstamp.h>
#include <linux/spi/spi.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "ksz_cfg_8463.h"


#define KS8463MLI_DEV0			"ksz8463"
#define KS8463MLI_DEV2			"ksz8463_2"

#define SW_DRV_RELDATE			"Feb 8, 2017"
#define SW_DRV_VERSION			"1.1.0"

/* -------------------------------------------------------------------------- */

#define HW_R(ks, reg)		spi_rdreg16(ks, reg)
#define HW_W(ks, reg, val)	spi_wrreg16(ks, reg, val)
#define HW_R8(ks, reg)		spi_rdreg8(ks, reg)
#define HW_W8(ks, reg, val)	spi_wrreg8(ks, reg, val)
#define HW_R16(ks, reg)		spi_rdreg16(ks, reg)
#define HW_W16(ks, reg, val)	spi_wrreg16(ks, reg, val)
#define HW_R32(ks, reg)		spi_rdreg32(ks, reg)
#define HW_W32(ks, reg, val)	spi_wrreg32(ks, reg, val)

#include "ksz_sw_phy.h"

#include "ksz_spi_net.h"

/* -------------------------------------------------------------------------- */

#define SPI_BYTE_ENABLE_S		4
#define SPI_ADDR_ENABLE_S		2
#define SPI_ADDR_S			11
#define SPI_ADDR_M			((1 << SPI_ADDR_S) - 1)
#define SPI_TURNAROUND_S		2

#define MK_BYTE(reg)			(1 << ((reg) & 3))
#define MK_WORD(reg)			(3 << ((reg) & 2))
#define MK_LONG(reg)			(0xf)

#define MK_OP(_byteen, _reg)		\
	((((_reg) >> SPI_ADDR_ENABLE_S) << SPI_BYTE_ENABLE_S) | _byteen)

#define KS_SPIOP_RD			0
#define KS_SPIOP_WR			\
	(1 << (SPI_ADDR_S - SPI_ADDR_ENABLE_S + SPI_BYTE_ENABLE_S))

/*
 * SPI register read/write calls.
 *
 * All these calls issue SPI transactions to access the chip's registers. They
 * all require that the necessary lock is held to prevent accesses when the
 * chip is busy transfering packet data (RX/TX FIFO accesses).
 */

/**
 * spi_wrreg - issue write register command
 * @ks:		The switch device structure.
 * @op:		The register address and byte enables in message format.
 * @val:	The value to write.
 * @rxl:	The length of data.
 *
 * This is the low level write call that issues the necessary spi message(s)
 * to write data to the register specified in @op.
 */
static void spi_wrreg(struct sw_priv *ks, unsigned op, unsigned val,
	unsigned txl)
{
	struct spi_hw_priv *hw_priv = ks->hw_dev;
	struct spi_transfer *xfer = &hw_priv->spi_xfer1;
	struct spi_message *msg = &hw_priv->spi_msg1;
	struct spi_device *spi = hw_priv->spidev;
	__le16 txb[4];
	int ret;

	if (!mutex_is_locked(&ks->lock))
		pr_alert("W not locked\n");
	op |= KS_SPIOP_WR;
	op <<= SPI_TURNAROUND_S;
	txb[0] = cpu_to_be16(op);
	txb[1] = cpu_to_le16(val);
	txb[2] = cpu_to_le16(val >> 16);

	xfer->tx_buf = txb;
	xfer->rx_buf = NULL;
	xfer->len = txl + 2;

	ret = spi_sync(spi, msg);
	if (ret < 0)
		pr_alert("spi_sync() failed\n");
}

/**
 * spi_wrreg32 - write 32bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void spi_wrreg32(struct sw_priv *ks, unsigned reg, unsigned val)
{
	spi_wrreg(ks, MK_OP(MK_LONG(reg), reg), val, 4);
}

/**
 * spi_wrreg16 - write 16bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void spi_wrreg16(struct sw_priv *ks, unsigned reg, unsigned val)
{
	spi_wrreg(ks, MK_OP(MK_WORD(reg), reg), val, 2);
}

/**
 * spi_wrreg8 - write 8bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void spi_wrreg8(struct sw_priv *ks, unsigned reg, unsigned val)
{
	spi_wrreg(ks, MK_OP(MK_BYTE(reg), reg), val, 1);
}

/**
 * ksz_rx_1msg - select whether to use one or two messages for spi read
 * @ks:		The device structure.
 *
 * Return whether to generate a single message with a tx and rx buffer
 * supplied to spi_sync(), or alternatively send the tx and rx buffers
 * as separate messages.
 *
 * Depending on the hardware in use, a single message may be more efficient
 * on interrupts or work done by the driver.
 *
 * This currently always returns false until we add some per-device data passed
 * from the platform code to specify which mode is better.
 */
static inline bool ksz_rx_1msg(struct spi_hw_priv *ks)
{
	return ks->rx_1msg;
}

/**
 * spi_rdreg - issue read register command and return the data
 * @ks:		The switch device structure.
 * @op:		The register address and byte enables in message format.
 * @rxb:	The RX buffer to return the result into.
 * @rxl:	The length of data expected.
 *
 * This is the low level read call that issues the necessary spi message(s)
 * to read data from the register specified in @op.
 */
static void spi_rdreg(struct sw_priv *ks, unsigned op, u8 *rxb, unsigned rxl)
{
	struct spi_hw_priv *hw_priv = ks->hw_dev;
	struct spi_transfer *xfer;
	struct spi_message *msg;
	struct spi_device *spi = hw_priv->spidev;
	__le16 *txb = (__le16 *) hw_priv->txd;
	u8 *trx = hw_priv->rxd;
	int ret;

	if (!mutex_is_locked(&ks->lock))
		pr_alert("R not locked\n");
	op |= KS_SPIOP_RD;
	op <<= SPI_TURNAROUND_S;
	txb[0] = cpu_to_be16(op);

	if (ksz_rx_1msg(hw_priv)) {
#if defined(CONFIG_SPI_PEGASUS) || defined(CONFIG_SPI_PEGASUS_MODULE)
		/*
		 * A hack to tell KSZ8692 SPI host controller the read command.
		 */
		txb[1] = 0;
		memcpy(trx, txb, 2 + 2);
		txb[1] ^= 0xffff;
#endif
		msg = &hw_priv->spi_msg1;
		xfer = &hw_priv->spi_xfer1;

		xfer->tx_buf = txb;
		xfer->rx_buf = trx;
		xfer->len = rxl + 2;
	} else {
		msg = &hw_priv->spi_msg2;
		xfer = hw_priv->spi_xfer2;

		xfer->tx_buf = txb;
		xfer->rx_buf = NULL;
		xfer->len = 2;

		xfer++;
		xfer->tx_buf = NULL;
		xfer->rx_buf = trx;
		xfer->len = rxl;
	}

	ret = spi_sync(spi, msg);
	if (ret < 0)
		pr_alert("read: spi_sync() failed\n");
	else if (ksz_rx_1msg(hw_priv))
		memcpy(rxb, trx + 2, rxl);
	else
		memcpy(rxb, trx, rxl);
}

/**
 * spi_rdreg8 - read 8 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 8bit register from the chip, returning the result.
 */
static u8 spi_rdreg8(struct sw_priv *ks, unsigned reg)
{
	u8 rxb[1];

	spi_rdreg(ks, MK_OP(MK_BYTE(reg), reg), rxb, 1);
	return rxb[0];
}

/**
 * spi_rdreg16 - read 16 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 16bit register from the chip, returning the result.
 */
static u16 spi_rdreg16(struct sw_priv *ks, unsigned reg)
{
	__le16 rx = 0;

	spi_rdreg(ks, MK_OP(MK_WORD(reg), reg), (u8 *) &rx, 2);
	return le16_to_cpu(rx);
}

/**
 * spi_rdreg32 - read 32 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 32bit register from the chip.
 *
 * Note, this read requires the address be aligned to 4 bytes.
 */
static u32 spi_rdreg32(struct sw_priv *ks, unsigned reg)
{
	__le32 rx = 0;

	WARN_ON(reg & 3);

	spi_rdreg(ks, MK_OP(MK_LONG(reg), reg), (u8 *) &rx, 4);
	return le32_to_cpu(rx);
}

/* -------------------------------------------------------------------------- */

/**
 * delay_micro - delay in microsecond
 * @microsec:	Number of microseconds to delay.
 *
 * This routine delays in microseconds.
 */
static inline void delay_micro(uint microsec)
{
	uint millisec = microsec / 1000;

	microsec %= 1000;
	if (millisec)
		mdelay(millisec);
	if (microsec)
		udelay(microsec);
}

/**
 * delay_milli - delay in millisecond
 * @millisec:	Number of milliseconds to delay.
 *
 * This routine delays in milliseconds.
 */
static void delay_milli(uint millisec)
{
	unsigned long ticks = millisec * HZ / 1000;

	if (!ticks || in_interrupt())
		mdelay(millisec);
	else {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(ticks);
	}
}

#define USE_SHOW_HELP
#include "ksz_common.c"

#ifdef CONFIG_1588_PTP
/* For ksz_request used by PTP or MRP driver. */
#include "ksz_req.c"
#endif

#ifndef CONFIG_KSZ_SWITCH_EMBEDDED
static inline void copy_old_skb(struct sk_buff *old, struct sk_buff *skb)
{
	skb->dev = old->dev;
	skb->sk = old->sk;
	skb->protocol = old->protocol;
	skb->ip_summed = old->ip_summed;
	skb->csum = old->csum;
	skb_shinfo(skb)->tx_flags = skb_shinfo(old)->tx_flags;
	skb_set_network_header(skb, ETH_HLEN);

	dev_kfree_skb(old);
}  /* copy_old_skb */
#endif

/* -------------------------------------------------------------------------- */

#define KSZSW_REGS_SIZE			0x800

static struct sw_regs {
	int start;
	int end;
} sw_regs_range[] = {
	{ 0x000, 0x1BA },
	{ 0x200, 0x398 },
	{ 0x400, 0x690 },
	{ 0x734, 0x736 },
	{ 0x748, 0x74E },
	{ 0, 0 }
};

static int check_sw_reg_range(unsigned addr)
{
	struct sw_regs *range = sw_regs_range;

	while (range->end > range->start) {
		if (range->start <= addr && addr < range->end)
			return true;
		range++;
	}
	return false;
}

static struct ksz_sw *get_sw_data(struct device *d)
{
	struct sw_priv *hw_priv = dev_get_drvdata(d);

	return &hw_priv->sw;
}

/* -------------------------------------------------------------------------- */

#define MIB_READ_INTERVAL		(HZ / 2)

static unsigned long next_jiffies;

static int exit_mib_read(struct ksz_sw *sw)
{
	if (sw->intr_using)
		return true;
	return false;
}  /* exit_mib_read */

static void sw_ena_intr(struct ksz_sw *sw)
{
	struct sw_priv *hw_priv = container_of(sw, struct sw_priv, sw);

	HW_W(sw->dev, REG_INT_MASK, hw_priv->intr_mask);
}  /* sw_ena_intr */

static u8 sw_r8(struct ksz_sw *sw, unsigned reg)
{
	return HW_R8(sw->dev, reg);
}

static u16 sw_r16(struct ksz_sw *sw, unsigned reg)
{
	return HW_R16(sw->dev, reg);
}

static u32 sw_r32(struct ksz_sw *sw, unsigned reg)
{
	return HW_R32(sw->dev, reg);
}

static void sw_w8(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W8(sw->dev, reg, val);
}

static void sw_w16(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W16(sw->dev, reg, val);
}

static void sw_w32(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W32(sw->dev, reg, val);
}

static void link_update_work(struct work_struct *work)
{
	struct ksz_port *port =
		container_of(work, struct ksz_port, link_update);
	struct ksz_sw *sw = port->sw;
	struct phy_device *phydev;
	struct ksz_port_info *info;
	int i;
	int link;

	/* This only matters when one phy device is used for the switch. */
	if (1 == sw->dev_count) {
		struct sw_priv *hw_priv = container_of(sw, struct sw_priv, sw);

		if (hw_priv->phy_id != port->linked->phy_id)
			hw_priv->phy_id = port->linked->phy_id;
	}
	for (i = 0; i < SWITCH_PORT_NUM; i++) {
		info = &sw->port_info[i];

		phydev = sw->phy[i + 1];
		phydev->link = (info->state == media_connected);
		phydev->speed = info->tx_rate / TX_RATE_UNIT;
		phydev->duplex = (info->duplex == 2);
	}

	for (i = 0; i < sw->eth_cnt; i++) {
		if (sw->eth_maps[i].port == port->first_port) {
			if (sw->eth_maps[i].phy_id != port->linked->phy_id)
				sw->eth_maps[i].phy_id = port->linked->phy_id;
			break;
		}
	}

	info = port->linked;
	phydev = sw->phy[port->first_port + 1];
	phydev->link = (info->state == media_connected);
	phydev->speed = info->tx_rate / TX_RATE_UNIT;
	phydev->duplex = (info->duplex == 2);
	if (phydev->attached_dev) {
		link = netif_carrier_ok(phydev->attached_dev);
		if (link != phydev->link) {
			if (phydev->link)
				netif_carrier_on(phydev->attached_dev);
			else
				netif_carrier_off(phydev->attached_dev);
			if (netif_msg_link(sw))
				pr_info("%s link %s\n",
					phydev->attached_dev->name,
					phydev->link ? "on" : "off");
		}
	}

	/* The switch is always linked; speed and duplex are also fixed. */
	if (sw->netdev[0]) {
		phydev = sw->netdev[0]->phydev;
		if (!phydev)
			phydev = sw->phydev;
		if (sw->net_ops->get_priv_port)
			port = sw->net_ops->get_priv_port(sw->netdev[0]);
	} else
		phydev = sw->phydev;
	if (phydev->attached_dev) {
		int phy_link;

		/* phydev settings may be changed by ethtool. */
		phydev->link = 1;
		phydev->speed = SPEED_100;
		phydev->duplex = 1;
		phydev->pause = 1;
		phy_link = (port->linked->state == media_connected);
		link = netif_carrier_ok(phydev->attached_dev);
		if (link != phy_link) {
			if (phy_link)
				netif_carrier_on(phydev->attached_dev);
			else
				netif_carrier_off(phydev->attached_dev);
			if (netif_msg_link(sw))
				pr_info("%s link %s\n",
					phydev->attached_dev->name,
					phy_link ? "on" : "off");
		}
		if (phydev->adjust_link)
			phydev->adjust_link(phydev->attached_dev);
	}

#ifdef CONFIG_KSZ_STP
	if (sw->features & STP_SUPPORT) {
		struct ksz_stp_info *stp = &sw->info->rstp;

		stp->ops->link_change(stp, true);
	}
#endif

#ifdef CONFIG_KSZ_HSR
	if (sw->features & HSR_HW) {
		struct ksz_hsr_info *hsr = &sw->info->hsr;

		if (hsr->ports[0] <= port->first_port &&
		    port->first_port <= hsr->ports[1])
			hsr->ops->check_announce(hsr);
	}
#endif
}  /* link_update_work */

#define USE_DIFF_PORT_PRIORITY
#include "ksz_sw.c"

/* -------------------------------------------------------------------------- */

/* debugfs code */
static int state_show(struct seq_file *seq, void *v)
{
	int i;
	int j;
	SW_D data[16 / SW_SIZE];
	struct sw_priv *ks = seq->private;

	for (i = 0; i < 0x100; i += 16) {
		seq_printf(seq, SW_SIZE_STR":\t", i);
		mutex_lock(&ks->lock);
		for (j = 0; j < 16 / SW_SIZE; j++)
			data[j] = HW_R(ks, i + j * SW_SIZE);
		mutex_unlock(&ks->lock);
		for (j = 0; j < 16 / SW_SIZE; j++)
			seq_printf(seq, SW_SIZE_STR" ", data[j]);
		seq_printf(seq, "\n");
	}
	return 0;
}

static int state_open(struct inode *inode, struct file *file)
{
	return single_open(file, state_show, inode->i_private);
}

static const struct file_operations state_fops = {
	.owner	= THIS_MODULE,
	.open	= state_open,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.release = single_release,
};

/**
 * create_debugfs - create debugfs directory and files
 * @ks:		The switch device structure.
 *
 * Create the debugfs entries for the specific device.
 */
static void create_debugfs(struct sw_priv *ks)
{
	struct dentry *root;
	char root_name[32];

	snprintf(root_name, sizeof(root_name), "%s",
		 dev_name(ks->dev));

	root = debugfs_create_dir(root_name, NULL);
	if (IS_ERR(root)) {
		pr_err("cannot create debugfs root\n");
		return;
	}

	ks->debug_root = root;
	ks->debug_file = debugfs_create_file("state", 0444, root,
		ks, &state_fops);
	if (IS_ERR(ks->debug_file))
		pr_err("cannot create debugfs state file\n");
}

static void delete_debugfs(struct sw_priv *ks)
{
	debugfs_remove(ks->debug_file);
	debugfs_remove(ks->debug_root);
}

/* -------------------------------------------------------------------------- */

#define USE_SPEED_LINK
#define USE_MIB
#include "ksz_sw_sysfs.c"

#ifdef CONFIG_1588_PTP
#include "ksz_ptp_sysfs.c"
#endif

static irqreturn_t sw_interrupt(int irq, void *phy_dat)
{
	struct phy_device *phydev = phy_dat;
	struct sw_priv *ks = phydev->bus->priv;

	if (IRQF_TRIGGER_LOW == ks->intr_mode)
		disable_irq_nosync(irq);
	atomic_inc(&phydev->irq_disable);
	ks->sw.intr_using = 1;
	schedule_work(&phydev->phy_queue);

	return IRQ_HANDLED;
}  /* sw_interrupt */

static void sw_change(struct work_struct *work)
{
	struct phy_device *phydev =
		container_of(work, struct phy_device, phy_queue);
	struct sw_priv *ks = phydev->bus->priv;
	struct ksz_sw *sw = &ks->sw;
	SW_D status;

	ks->intr_working = true;
	mutex_lock(&ks->hwlock);
	mutex_lock(&ks->lock);
	sw->intr_using++;
	status = HW_R(ks, REG_INT_STATUS);
	status &= ks->intr_mask;
	if (status & INT_PHY) {
		HW_W(ks, REG_INT_STATUS, INT_PHY);
		status &= ~INT_PHY;
		schedule_delayed_work(&ks->link_read, 0);
	}
#ifdef CONFIG_1588_PTP
	do {
		struct ptp_info *ptp = &sw->ptp_hw;

		if (ptp->ops->proc_intr) {
			ptp->ops->proc_intr(ptp);
			status = 0;
		}
	} while (0);
#endif
	sw->intr_using--;
	mutex_unlock(&ks->lock);
	if (status) {
		mutex_lock(&ks->lock);
		HW_W(ks, REG_INT_STATUS, status);
		mutex_unlock(&ks->lock);
	}
	mutex_unlock(&ks->hwlock);
	sw->intr_using = 0;

	atomic_dec(&phydev->irq_disable);
	if (IRQF_TRIGGER_LOW == ks->intr_mode)
		enable_irq(ks->irq);
}  /* sw_change */

static int sw_start_interrupt(struct sw_priv *ks, const char *name)
{
	struct phy_device *phydev = ks->phydev;
	int err = 0;

	INIT_WORK(&phydev->phy_queue, sw_change);

	atomic_set(&phydev->irq_disable, 0);
	if (request_irq(ks->irq, sw_interrupt, ks->intr_mode, name,
			phydev) < 0) {
		printk(KERN_WARNING "%s: Can't get IRQ %d (PHY)\n",
			phydev->bus->name,
			ks->irq);
		phydev->irq = PHY_POLL;
		return 0;
	}

	return err;
}  /* sw_start_interrupt */

static void sw_stop_interrupt(struct sw_priv *ks)
{
	struct phy_device *phydev = ks->phydev;

	free_irq(ks->irq, phydev);
	cancel_work_sync(&phydev->phy_queue);
	while (atomic_dec_return(&phydev->irq_disable) >= 0)
		enable_irq(ks->irq);
}  /* sw_stop_interrupt */

/* -------------------------------------------------------------------------- */

#define KSZ8463_ID_HI		0x0022

#define KSZ8463_SW_ID		0x8463
#define PHY_ID_KSZ_SW		((KSZ8463_ID_HI << 16) | KSZ8463_SW_ID)

static int kszphy_config_init(struct phy_device *phydev)
{
	return 0;
}

static struct phy_driver kszsw_phy_driver = {
	.phy_id		= PHY_ID_KSZ_SW,
	.phy_id_mask	= 0x00ffffff,
	.name		= "Microchip KSZ8463 Switch",
	.features	= (PHY_BASIC_FEATURES |	SUPPORTED_Pause),
	.flags		= PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT,
	.config_init	= kszphy_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.driver		= { .owner = THIS_MODULE, },
};

static int ksz_mii_addr(int *reg, int *bank)
{
	int ret;

	ret = (*reg & 0xC000) >> ADDR_SHIFT;
	*bank = (*reg & 0x3000) >> BANK_SHIFT;
	*reg &= 0x0FFF;
	return ret;
}

/*
 * Tha  2011/03/11
 * The hardware register reads low word first of PHY id instead of high word.
 */
static inline int actual_reg(int regnum)
{
	if (2 == regnum)
		regnum = 3;
	else if (3 == regnum)
		regnum = 2;
	return regnum;
}

static int ksz_mii_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct sw_priv *ks = bus->priv;
	int addr;
	int bank;
	int ret = 0xffff;

	if (phy_id > SWITCH_PORT_NUM)
		return 0xffff;

	addr = ksz_mii_addr(&regnum, &bank);

	mutex_lock(&ks->lock);
	switch (addr) {
	case ADDR_8:
		ret = HW_R8(ks, regnum);
		break;
	case ADDR_16:
		ret = HW_R16(ks, regnum);
		break;
	case ADDR_32:
		ret = HW_R32(ks, regnum);
		break;
	default:
		if (regnum < 6) {
			int r;

			regnum = actual_reg(regnum);
			if (0 == phy_id)
				phy_id = ks->phy_id;
			else {
				int n;
				struct ksz_sw *sw = &ks->sw;

				/*
				 * Get the represented PHY id when using
				 * multiple ports.
				 */
				for (n = 0; n < sw->eth_cnt; n++) {
					if (sw->eth_maps[n].port + 1 ==
					    phy_id) {
						phy_id = sw->eth_maps[n].phy_id;
						break;
					}
				}
			}
			if (2 == phy_id)
				r = PHY2_REG_CTRL;
			else
				r = PHY1_REG_CTRL;
			ret = HW_R16(ks, r + regnum * 2);
			if (2 == regnum)
				ret = KSZ8463_SW_ID;
		} else
			ret = 0;
	}
	mutex_unlock(&ks->lock);
	return ret;
}  /* ksz_mii_read */

static int ksz_mii_write(struct mii_bus *bus, int phy_id, int regnum, u16 val)
{
	static int last_reg;
	static int last_val;
	struct sw_priv *ks = bus->priv;
	int addr;
	int bank;
	int reg;

	if (phy_id > SWITCH_PORT_NUM)
		return -EINVAL;

	reg = regnum;
	addr = ksz_mii_addr(&regnum, &bank);

	mutex_lock(&ks->lock);
	switch (addr) {
	case ADDR_8:
		HW_W8(ks, regnum, val);
		break;
	case ADDR_16:
		HW_W16(ks, regnum, val);
		break;
	case ADDR_32:
		/*
		 * The phy_write interface allows only 16-bit value.  Break
		 * the 32-bit write into two calls for SPI efficiency.
		 */

		/* Previous write to high word. */
		if (last_reg == reg + 2) {
			last_val <<= 16;
			last_val |= val;
			HW_W32(ks, regnum, last_val);
			last_reg = 0;
		} else {
			/* Somebody has written to different address! */
			if (last_reg) {
				int last_bank;

				addr = ksz_mii_addr(&last_reg, &last_bank);
				HW_W16(ks, last_reg, last_val);
				last_reg = 0;
			}

			/* Cache the 16-bit write to high word. */
			if (reg & 3) {
				last_reg = reg;
				last_val = val;

			/* Did not find the previous write to high word.*/
			} else
				HW_W16(ks, regnum, val);
		}
		break;
	default:
		if (regnum < 6) {
			int i;
			int r;
			int first;
			int last;
			struct ksz_sw *sw = &ks->sw;

			if (0 == phy_id) {
				first = 0;
				last = SWITCH_PORT_NUM;
			} else {
				int n;
				int f;
				int l;

				first = phy_id - 1;
				last = phy_id;
				for (n = 0; n < sw->eth_cnt; n++) {
					f = sw->eth_maps[n].port + 1;
					l = f + sw->eth_maps[n].cnt;
					if (f <= phy_id && phy_id < l) {
						first = sw->eth_maps[n].port;
						last = first +
							sw->eth_maps[n].cnt;
						break;
					}
				}
			}

			/* PHY device driver resets or powers down the PHY. */
			if (0 == regnum &&
			    (val & (PHY_RESET | PHY_POWER_DOWN)))
				break;
			for (i = first; i < last; i++) {
				if (i)
					r = PHY2_REG_CTRL;
				else
					r = PHY1_REG_CTRL;
				HW_W16(ks, r + regnum * 2, val);
			}
		}
		break;
	}
	mutex_unlock(&ks->lock);
	return 0;
}  /* ksz_mii_write */

static int driver_installed;

static int ksz_mii_init(struct sw_priv *ks)
{
	struct platform_device *pdev;
	struct mii_bus *bus;
	int err;
	int i;

	pdev = platform_device_register_simple("Switch MII bus", ks->sw.id,
		NULL, 0);
	if (!pdev)
		return -ENOMEM;

	bus = mdiobus_alloc();
	if (bus == NULL) {
		err = -ENOMEM;
		goto mii_init_reg;
	}

	if (!driver_installed) {
		err = phy_driver_register(&kszsw_phy_driver);
		if (err)
			goto mii_init_free_mii_bus;
		driver_installed = true;
	}

	bus->name = "Switch MII bus",
	bus->read = ksz_mii_read;
	bus->write = ksz_mii_write;
	snprintf(bus->id, MII_BUS_ID_SIZE, "sw.%d", ks->sw.id);
	bus->parent = &pdev->dev;
	bus->phy_mask = ~((1 << (ks->sw.mib_port_cnt + 1)) - 1);
	bus->priv = ks;
	bus->irq = ks->bus_irqs;

	for (i = 0; i < PHY_MAX_ADDR; i++)
		bus->irq[i] = ks->irq;

	ks->phy_id = 1;
	err = mdiobus_register(bus);
	if (err < 0)
		goto mii_init_free_mii_bus;

	if (!bus->phy_map[0]) {
		printk(KERN_WARNING "No PHY detected\n");
		mdiobus_unregister(bus);
		err = -ENODEV;
		goto mii_init_free_mii_bus;
	}

	for (i = 0; i < PHY_MAX_ADDR; i++)
		if (bus->phy_map[i]) {
			struct phy_priv *phydata;
			struct ksz_port *port;
			int p = i;

			if (!p)
				p = 1;

			phydata = kzalloc(sizeof(struct phy_priv), GFP_KERNEL);
			if (!phydata) {
				err = -ENOMEM;
				goto mii_init_free_mii_bus;
			}
			port = &ks->ports[i];
			phydata->port = port;
			port->sw = &ks->sw;
			port->first_port = p - 1;
			port->port_cnt = 1;
			port->mib_port_cnt = 1;
			port->flow_ctrl = PHY_FLOW_CTRL;
			port->linked = &ks->sw.port_info[port->first_port];
			INIT_WORK(&port->link_update, link_update_work);
			phydata->state = bus->phy_map[i]->state;
			bus->phy_map[i]->priv = phydata;
		}

	ks->bus = bus;
	ks->pdev = pdev;
	ks->phydev = bus->phy_map[0];
	ks->phydev->interface = ks->sw.interface;

	/* The switch is always linked; speed and duplex are also fixed. */
	ks->phydev->link = 1;
	ks->phydev->speed = SPEED_100;
	ks->phydev->duplex = 1;
	ks->phydev->pause = 1;

	return 0;

mii_init_free_mii_bus:
	for (i = 0; i < PHY_MAX_ADDR; i++)
		if (bus->phy_map[i])
			kfree(bus->phy_map[i]->priv);
	if (driver_installed) {
		phy_driver_unregister(&kszsw_phy_driver);
		driver_installed = false;
	}
	mdiobus_free(bus);

mii_init_reg:
	platform_device_unregister(pdev);

	return err;
}  /* ksz_mii_init */

static void ksz_mii_exit(struct sw_priv *ks)
{
	int i;
	struct platform_device *pdev = ks->pdev;
	struct mii_bus *bus = ks->bus;

	if (ks->irq > 0) {
		mutex_lock(&ks->lock);
		HW_W(ks, TS_INT_ENABLE, 0);
		HW_W(ks, TRIG_INT_ENABLE, 0);
		HW_W(ks, REG_INT_MASK, 0);
		mutex_unlock(&ks->lock);
		sw_stop_interrupt(ks);
	}
	for (i = 0; i < PHY_MAX_ADDR; i++)
		if (bus->phy_map[i]) {
			struct ksz_port *port;

			port = &ks->ports[i];
			flush_work(&port->link_update);
			kfree(bus->phy_map[i]->priv);
		}
	mdiobus_unregister(bus);
	if (driver_installed) {
		phy_driver_unregister(&kszsw_phy_driver);
		driver_installed = false;
	}
	mdiobus_free(bus);
	platform_device_unregister(pdev);
}  /* ksz_mii_exit */

/* driver bus management functions */

static void determine_rate(struct ksz_sw *sw, struct ksz_port_mib *mib)
{
	int j;

	for (j = 0; j < 2; j++) {
		if (mib->rate[j].last) {
			int offset;
			u64 cnt;
			u64 last_cnt;
			unsigned long diff = jiffies - mib->rate[j].last;

			if (0 == j)
				offset = MIB_RX_LO_PRIO;
			else
				offset = MIB_TX_LO_PRIO;
			cnt = mib->counter[offset] + mib->counter[offset + 1];
			last_cnt = cnt;
			cnt -= mib->rate[j].last_cnt;
			if (cnt > 1000000 && diff >= 100) {
				u32 rem;
				u64 rate = cnt;

				rate *= 8;
				diff *= 10 * 100;
				rate = div_u64_rem(rate, diff, &rem);
				mib->rate[j].last = jiffies;
				mib->rate[j].last_cnt = last_cnt;
				if (mib->rate[j].peak < (u32) rate)
					mib->rate[j].peak = (u32) rate;
			}
		} else
			mib->rate[j].last = jiffies;
	}
}  /* determine_rate */

static void ksz8463_mib_read_work(struct work_struct *work)
{
	struct sw_priv *hw_priv =
		container_of(work, struct sw_priv, mib_read);
	struct ksz_sw *sw = &hw_priv->sw;
	struct ksz_port_mib *mib;
	int i;

	next_jiffies = jiffies;
	for (i = 0; i < sw->mib_port_cnt; i++) {
		mib = &sw->port_mib[i];

		/* Reading MIB counters or requested to read. */
		if (mib->cnt_ptr || 1 == hw_priv->counter[i].read) {

			/* Need to process interrupt. */
			if (port_r_cnt(sw, i))
				return;
			hw_priv->counter[i].read = 0;

			/* Finish reading counters. */
			if (0 == mib->cnt_ptr) {
				hw_priv->counter[i].read = 2;
				wake_up_interruptible(
					&hw_priv->counter[i].counter);
				if (i != sw->HOST_PORT)
					determine_rate(sw, mib);
			}
		} else if (jiffies >= hw_priv->counter[i].time) {
			/* Only read MIB counters when the port is connected. */
			if (media_connected == sw->port_state[i].state)
				hw_priv->counter[i].read = 1;

			/* Read dropped counters. */
			else
				mib->cnt_ptr = SWITCH_COUNTER_NUM;
			next_jiffies += MIB_READ_INTERVAL * sw->mib_port_cnt;
			hw_priv->counter[i].time = next_jiffies;

		/* Port is just disconnected. */
		} else if (sw->port_state[i].link_down) {
			sw->port_state[i].link_down = 0;

			/* Read counters one last time after link is lost. */
			hw_priv->counter[i].read = 1;
		}
	}
}  /* ksz8463_mib_read_work */

static void copy_port_status(struct ksz_port *src, struct ksz_port *dst)
{
	dst->duplex = src->duplex;
	dst->speed = src->speed;
	dst->force_link = src->force_link;
	dst->linked = src->linked;
}

static void link_read_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct sw_priv *hw_priv =
		container_of(dwork, struct sw_priv, link_read);
	struct ksz_sw *sw = &hw_priv->sw;
	struct phy_device *phydev;
	struct ksz_port *port = NULL;
	struct ksz_port *sw_port = NULL;
	int i;
	int changes = 0;
	int s = 1;

	if (1 == sw->dev_count || 1 == sw->dev_offset)
		s = 0;
	if (sw->dev_offset) {
		struct phy_priv *phydata;
		struct net_device *dev = sw->netdev[0];

		phydev = sw->phydev;
		phydata = phydev->priv;
		if (dev && sw->net_ops->get_priv_port)
			sw_port = sw->net_ops->get_priv_port(dev);
		else
			sw_port = phydata->port;
	}
	sw->ops->acquire(sw);
	for (i = sw->dev_offset; i < sw->dev_count + sw->dev_offset; i++) {
		struct phy_priv *phydata;
		struct net_device *dev = sw->netdev[i];

		phydev = sw->phy[i + s];
		if (sw->features & SW_VLAN_DEV)
			phydev = sw->phy[sw->eth_maps[i].port + 1];
		phydata = phydev->priv;
		if (dev && sw->net_ops->get_priv_port)
			port = sw->net_ops->get_priv_port(dev);
		else
			port = phydata->port;
		changes |= port_get_link_speed(port);

		/* Copy all port information for user access. */
		if (port != phydata->port) {
			copy_port_status(port, phydata->port);
			if (phydata != hw_priv->phydev->priv) {
				phydata = hw_priv->phydev->priv;
				copy_port_status(port, phydata->port);
			}
		}
	}
	sw->ops->release(sw);

	/* Not to read PHY registers unnecessarily if no link change. */
	if (!changes)
		return;

#ifdef CONFIG_1588_PTP
	if (sw->features & PTP_HW) {
		struct ptp_info *ptp = &sw->ptp_hw;

		for (i = 0; i < ptp->ports; i++)
			ptp->linked[i] = (sw->port_info[i].state ==
				media_connected);
	}
#endif
	if (!sw->dev_offset || (media_connected == sw_port->linked->state))
		return;

	for (i = sw->dev_offset; i < sw->dev_count + sw->dev_offset; i++) {
		struct phy_priv *phydata;
		struct net_device *dev = sw->netdev[i];

		phydev = sw->phy[i + s];
		if (sw->features & SW_VLAN_DEV)
			phydev = sw->phy[sw->eth_maps[i].port + 1];
		phydata = phydev->priv;
		if (dev && sw->net_ops->get_priv_port)
			port = sw->net_ops->get_priv_port(dev);
		else
			port = phydata->port;
		if (media_connected == port->linked->state) {
			sw_port->linked = port->linked;
			hw_priv->phy_id = port->linked->phy_id;
			break;
		}
	}
}  /* link_read_work */

/*
 * Hardware monitoring
 */

static void ksz8463_mib_monitor(unsigned long ptr)
{
	struct sw_priv *hw_priv = (struct sw_priv *) ptr;

	schedule_work(&hw_priv->mib_read);

	ksz_update_timer(&hw_priv->mib_timer_info);
}  /* ksz8463_mib_monitor */

static void ksz8463_dev_monitor(unsigned long ptr)
{
	struct sw_priv *hw_priv = (struct sw_priv *) ptr;
	struct phy_device *phydev;
	struct phy_priv *priv;
	int i;

	for (i = 0; i < TOTAL_PORT_NUM; i++) {
		phydev = hw_priv->bus->phy_map[i];
		if (!phydev)
			continue;
		priv = phydev->priv;
		if (priv->state != phydev->state) {
			priv->state = phydev->state;
			if (PHY_UP == phydev->state ||
			    PHY_RESUMING == phydev->state)
				schedule_work(&priv->port->link_update);
		}
	}
	if (!hw_priv->intr_working)
		schedule_delayed_work(&hw_priv->link_read, 0);

	ksz_update_timer(&hw_priv->monitor_timer_info);
}  /* ksz8463_dev_monitor */

#ifdef CONFIG_NET_DSA_TAG_TAIL
#include "ksz_dsa.c"
#endif

static int fiber;
static int intr_mode;
static int rx_1msg;
static int spi_bus;

#define MAX_SPI_DEVICES		2

static int sw_device_present;

static int ksz8463_probe(struct spi_device *spi)
{
	struct spi_hw_priv *hw_priv;
	struct sw_priv *ks;
	struct ksz_sw *sw;
	struct ksz_port *port;
	struct phy_device *phydev;
	struct phy_priv *priv;
	u16 id;
	int cnt;
	int i;
	int mib_port_count;
	int pi;
	int port_count;
	int ret;

	spi->bits_per_word = 8;

	ks = kzalloc(sizeof(struct sw_priv), GFP_KERNEL);
	if (!ks)
		return -ENOMEM;

	ks->hw_dev = kzalloc(sizeof(struct spi_hw_priv), GFP_KERNEL);
	if (!ks->hw_dev) {
		kfree(ks);
		return -ENOMEM;
	}
	hw_priv = ks->hw_dev;

	hw_priv->rx_1msg = rx_1msg;
	hw_priv->spidev = spi;

	/* initialise pre-made spi transfer messages */

	spi_message_init(&hw_priv->spi_msg1);
	spi_message_add_tail(&hw_priv->spi_xfer1, &hw_priv->spi_msg1);

	spi_message_init(&hw_priv->spi_msg2);
	spi_message_add_tail(&hw_priv->spi_xfer2[0], &hw_priv->spi_msg2);
	spi_message_add_tail(&hw_priv->spi_xfer2[1], &hw_priv->spi_msg2);

	ks->intr_mode = intr_mode ? IRQF_TRIGGER_FALLING :
		IRQF_TRIGGER_LOW;
	ks->irq = spi->irq;
	ks->dev = &spi->dev;

	dev_set_drvdata(ks->dev, ks);

	mutex_init(&ks->hwlock);
	mutex_init(&ks->lock);

	/* simple check for a valid chip being connected to the bus */
	mutex_lock(&ks->lock);
	id = HW_R(ks, REG_SWITCH_SIDER);
	mutex_unlock(&ks->lock);
	if ((id & CIDER_ID_MASK) != CIDER_ID_8463 &&
			(id & CIDER_ID_MASK) != CIDER_ID_8463_RLI) {
		dev_err(ks->dev, "failed to read device ID(0x%x)\n", id);
		ret = -ENODEV;
		goto err_sw;
	}
	dev_info(ks->dev, "chip id 0x%x, spi bus %d\n", id,
		spi->master->bus_num);

	sw = &ks->sw;
	mutex_init(&sw->lock);
	sw->hwlock = &ks->hwlock;
	sw->reglock = &ks->lock;

	sw->dev_count = 1;

	port_count = SWITCH_PORT_NUM;
	mib_port_count = SWITCH_PORT_NUM;

	sw->mib_cnt = TOTAL_SWITCH_COUNTER_NUM;
	sw->mib_port_cnt = TOTAL_PORT_NUM;
	sw->port_cnt = SWITCH_PORT_NUM;
	sw->PORT_MASK = (1 << sw->mib_port_cnt) - 1;
	sw->HOST_PORT = SWITCH_PORT_NUM;
	sw->HOST_MASK = (1 << sw->HOST_PORT);

	sw->dev = ks;
	sw->id = sw_device_present;

	sw->info = kzalloc(sizeof(struct ksz_sw_info), GFP_KERNEL);
	if (!sw->info) {
		ret = -ENOMEM;
		goto err_sw;
	}

	sw->reg = &sw_reg_ops;
	sw->net_ops = &sw_net_ops;
	sw->ops = &sw_ops;

	INIT_DELAYED_WORK(&ks->link_read, link_read_work);

	ret = ksz_mii_init(ks);
	if (ret)
		goto err_mii;

	sw->multi_dev |= multi_dev;
	sw->stp |= stp;
	sw->fast_aging |= fast_aging;
	sw_setup_zone(sw);

	sw->phydev = ks->phydev;
	sw->counter = ks->counter;
	sw->monitor_timer_info = &ks->monitor_timer_info;
	sw->link_read = &ks->link_read;

	sw_init_mib(sw);

	for (i = 0; i < port_count; i++) {
		if (fiber & (1 << i))
			sw->port_info[i].fiber = true;
	}

	for (i = 0; i < TOTAL_PORT_NUM; i++)
		init_waitqueue_head(&ks->counter[i].counter);

	create_debugfs(ks);

#ifdef CONFIG_KSZ_STP
	ksz_stp_init(&sw->info->rstp, sw);
#endif
#ifdef CONFIG_KSZ_HSR
	if (sw->features & HSR_HW)
		ksz_hsr_init(&sw->info->hsr, sw);
#endif
	sw->ops->acquire(sw);
	sw_init(sw);
	sw_setup(sw);
	sw_enable(sw);
	sw->ops->release(sw);
	sw->ops->init(sw);

#ifndef CONFIG_KSZ8463_EMBEDDED
	init_sw_sysfs(sw, &ks->sysfs, ks->dev);
#endif
	ret = sysfs_create_bin_file(&ks->dev->kobj,
		&kszsw_registers_attr);
	sema_init(&ks->proc_sem, 1);

	for (cnt = 0, pi = 0; cnt < port_count; cnt++, pi++) {
		/*
		 * Initialize to invalid value so that link detection
		 * is done.
		 */
		sw->port_info[pi].partner = 0xFF;
		sw->port_info[pi].state = media_disconnected;
		sw->port_info[pi].phy_id = pi + 1;
	}
	sw->interface = PHY_INTERFACE_MODE_MII;
	for (i = 0; i <= SWITCH_PORT_NUM; i++) {
		sw->phy[i] = ks->bus->phy_map[i];
	}
	phydev = sw->phy[0];
	priv = phydev->priv;
	port = priv->port;
	port->port_cnt = port_count;
	port->mib_port_cnt = mib_port_count;
	port->flow_ctrl = PHY_FLOW_CTRL;

	INIT_WORK(&ks->mib_read, ksz8463_mib_read_work);

	/* 500 ms timeout */
	ksz_init_timer(&ks->mib_timer_info, 500 * HZ / 1000,
		ksz8463_mib_monitor, ks);
	ksz_init_timer(&ks->monitor_timer_info, 100 * HZ / 1000,
		ksz8463_dev_monitor, ks);

	ksz_start_timer(&ks->mib_timer_info, ks->mib_timer_info.period);
	if (!sw->multi_dev && !sw->stp)
		ksz_start_timer(&ks->monitor_timer_info,
			ks->monitor_timer_info.period * 10);

	sw_device_present++;

#ifdef CONFIG_1588_PTP
	sw->features |= PTP_HW;
	if (sw->features & PTP_HW) {
		struct ptp_info *ptp = &sw->ptp_hw;

		ptp->reg = &ptp_reg_ops;
		ptp->ops = &ptp_ops;
		ptp->parent = ks->dev;
		ptp->ops->init(ptp, sw->info->mac_addr);
		init_ptp_sysfs(&ks->ptp_sysfs, ks->dev);
	}
#endif

#ifdef CONFIG_NET_DSA_TAG_TAIL
	ksz_dsa_init();
#endif

	if (ks->irq <= 0)
		return 0;
	ks->intr_mask = INT_PHY | INT_TIMESTAMP | INT_TRIG_OUTPUT;
	mutex_lock(&ks->lock);
	HW_W(ks, TS_INT_ENABLE, 0);
	HW_W(ks, TS_INT_STATUS, 0xffff);
	mutex_unlock(&ks->lock);
	ret = sw_start_interrupt(ks, dev_name(ks->dev));
	if (ret < 0)
		printk(KERN_WARNING "No switch interrupt\n");
	else {
		mutex_lock(&ks->lock);
		HW_W(ks, REG_INT_MASK, ks->intr_mask);
		mutex_unlock(&ks->lock);
	}

	return 0;

err_mii:
	kfree(sw->info);

err_sw:
	kfree(ks->hw_dev);
	kfree(ks);

	return ret;
}

static int ksz8463_remove(struct spi_device *spi)
{
	struct sw_priv *ks = dev_get_drvdata(&spi->dev);
	struct ksz_sw *sw = &ks->sw;

#ifdef CONFIG_NET_DSA_TAG_TAIL
	ksz_dsa_cleanup();
#endif
#ifdef CONFIG_1588_PTP
	if (sw->features & PTP_HW) {
		struct ptp_info *ptp = &sw->ptp_hw;

		exit_ptp_sysfs(&ks->ptp_sysfs, ks->dev);
		ptp->ops->exit(ptp);
	}
#endif
	ksz_mii_exit(ks);
	ksz_stop_timer(&ks->monitor_timer_info);
	ksz_stop_timer(&ks->mib_timer_info);
	flush_work(&ks->mib_read);

	sysfs_remove_bin_file(&ks->dev->kobj, &kszsw_registers_attr);

#ifndef CONFIG_KSZ8463_EMBEDDED
	exit_sw_sysfs(sw, &ks->sysfs, ks->dev);
#endif
	sw->ops->exit(sw);
	cancel_delayed_work_sync(&ks->link_read);

	delete_debugfs(ks);

#ifdef CONFIG_KSZ_STP
	ksz_stp_exit(&sw->info->rstp);
#endif
	kfree(sw->info);
	kfree(ks->hw_dev);
	kfree(ks);

	return 0;
}

static const struct of_device_id ksz8463_dt_ids[] = {
	{ .compatible = "microchip,ksz8463" },
	{},
};
MODULE_DEVICE_TABLE(of, ksz8463_dt_ids);

static struct spi_driver ksz8463_driver = {
	.driver = {
		.name = KS8463MLI_DEV0,
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(ksz8463_dt_ids),
	},
	.probe = ksz8463_probe,
	.remove = ksz8463_remove,
};

#if defined(CONFIG_SPI_FTDI) && defined(CONFIG_ARCH_MICREL_PEGASUS)
static void ksz8463_late_init(void)
{
	spi_register_driver(&ksz8463_driver);
}
#endif

static int __init ksz8463_init(void)
{
	if (spi_bus == 0)
		sprintf((char *) ksz8463_driver.driver.name, KS8463MLI_DEV0);
	else
		sprintf((char *) ksz8463_driver.driver.name, KS8463MLI_DEV2);

#if defined(CONFIG_SPI_FTDI) && defined(CONFIG_ARCH_MICREL_PEGASUS)
	pegasus_register_late_call(ksz8463_late_init);
	return 0;
#else
	return spi_register_driver(&ksz8463_driver);
#endif
}

static void __exit ksz8463_exit(void)
{
	spi_unregister_driver(&ksz8463_driver);
}

#ifndef CONFIG_KSZ8463_EMBEDDED
subsys_initcall(ksz8463_init);
module_exit(ksz8463_exit);

module_param(fast_aging, int, 0);
module_param(multi_dev, int, 0);
module_param(stp, int, 0);
MODULE_PARM_DESC(fast_aging, "Fast aging");
MODULE_PARM_DESC(multi_dev, "Multiple device interfaces");
MODULE_PARM_DESC(stp, "STP support");
#endif

module_param(fiber, int, 0);
MODULE_PARM_DESC(fiber, "Use fiber in ports");

module_param(intr_mode, int, 0);
MODULE_PARM_DESC(intr_mode,
	"Configure which interrupt mode to use(0=level low, 1=falling)");

module_param(rx_1msg, int, 0);
MODULE_PARM_DESC(rx_1msg,
	"Configure whether receive one message is used");

module_param(spi_bus, int, 0);
MODULE_PARM_DESC(spi_bus,
	"Configure which spi master to use(0=KSZ8692, 2=FTDI)");

#ifndef CONFIG_KSZ8463_EMBEDDED
MODULE_DESCRIPTION("Microchip KSZ8463 MLI Switch Driver");
MODULE_AUTHOR("Tristram Ha <Tristram.Ha@microchip.com>");
MODULE_LICENSE("GPL");

MODULE_ALIAS("spi:ksz8463");
#endif
