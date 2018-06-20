/**
 * Microchip KSZ9897 I2C driver
 *
 * Copyright (c) 2015-2017 Microchip Technology Inc.
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
#define DEBUG_MSG
#endif

#ifndef CONFIG_KSZ_SWITCH_EMBEDDED
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
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
#include <linux/i2c.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#define MAX_REQUEST_SIZE		80

#include "ksz_cfg_9897.h"


#if 1
#define NO_EEE
#endif


#ifdef CONFIG_KSZ_DLR
/* Have ACL to handle beacon timeout. */
#define CONFIG_HAVE_ACL_HW

/* Have DLR to transmit beacons. */
#define CONFIG_HAVE_DLR_HW
#endif

#ifdef CONFIG_KSZ_HSR
#define CONFIG_HAVE_HSR_HW
#endif

#if 0
#define USE_MII_PHY
#endif
#if 0
#define USE_RGMII_PHY
#endif
#if 0
#define USE_MII_MODE
#endif
#if 0
#define USE_GMII_MODE
#endif
#if 0
#define USE_RMII_MODE
#endif
#if 0
#define USE_RGMII_MODE
#endif
#if 0
#define USE_GMII_100_MODE
#endif
#if 0
#define USE_10_MBIT_MODE
#ifndef USE_GMII_100_MODE
#define USE_GMII_100_MODE
#endif
#endif
#if 0
#define USE_HALF_DUPLEX
#endif


#define SW_DRV_RELDATE			"Feb 8, 2017"
#define SW_DRV_VERSION			"1.1.0"

/* -------------------------------------------------------------------------- */

#define HW_R(ks, reg)		i2c_rdreg8(ks, reg)
#define HW_W(ks, reg, val)	i2c_wrreg8(ks, reg, val)
#define HW_R8(ks, reg)		i2c_rdreg8(ks, reg)
#define HW_W8(ks, reg, val)	i2c_wrreg8(ks, reg, val)
#define HW_R16(ks, reg)		i2c_rdreg16(ks, reg)
#define HW_W16(ks, reg, val)	i2c_wrreg16(ks, reg, val)
#define HW_R24(ks, reg)		i2c_rdreg24(ks, reg)
#define HW_W24(ks, reg, val)	i2c_wrreg24(ks, reg, val)
#define HW_R32(ks, reg)		i2c_rdreg32(ks, reg)
#define HW_W32(ks, reg, val)	i2c_wrreg32(ks, reg, val)

#include "ksz_sw_phy.h"

#include "ksz_spi_net.h"

/* -------------------------------------------------------------------------- */

#define contain_reg(addr, len, reg)	\
	(addr <= (reg) && (reg) <= (addr + len - 1))

static void i2c_chk_regs(struct ksz_sw *sw, u32 addr, u8 *val, size_t txl)
{
	int i;
	u32 port_reg;

	port_reg = REG_PTP_MSG_CONF1 + 1;
	if contain_reg(addr, txl, port_reg) {
		i = port_reg - addr;
		if (val[i] & PTP_ENABLE)
			sw->overrides |= PTP_TAG;
		else
			sw->overrides &= ~PTP_TAG;

/* KSZ9567 S1 needs to have PTP tag all the time. */
#if 1
		if (!(sw->features & NEW_CAP) &&
		    sw->TAIL_TAG_LOOKUP >= 0x100)
			sw->overrides |= PTP_TAG;
#endif
	}
	port_reg = PORT_CTRL_ADDR(sw->HOST_PORT, REG_PORT_CTRL_0);
	if contain_reg(addr, txl, port_reg) {
		i = port_reg - addr;
		if (val[i] & PORT_TAIL_TAG_ENABLE)
			sw->overrides |= TAIL_TAGGING;
		else
			sw->overrides &= ~TAIL_TAGGING;
	}
}  /* i2c_chk_regs */

/*
 * I2C register read/write calls.
 *
 * All these calls issue I2C transactions to access the chip's registers. They
 * all require that the necessary lock is held to prevent accesses when the
 * chip is busy transfering packet data (RX/TX FIFO accesses).
 */

/**
 * i2c_wrreg - issue write register command
 * @ks:		The switch device structure.
 * @addr:	The register address.
 * @val:	The value to write.
 * @txl:	The length of data.
 *
 * This is the low level write call that issues the necessary i2c message(s)
 * to write data to the register specified in @addr.
 */
static void i2c_wrreg(struct sw_priv *ks, u32 addr, void *txb, size_t txl)
{
	struct i2c_hw_priv *hw_priv = ks->hw_dev;
	struct i2c_msg msg;
	struct i2c_client *i2c = hw_priv->i2cdev;
	struct i2c_adapter *adapter = i2c->adapter;

	if (!mutex_is_locked(&ks->lock))
		pr_alert("W not locked\n");

	hw_priv->txd[0] = (u8)(addr >> 8);
	hw_priv->txd[1] = (u8) addr;

	memcpy(&hw_priv->txd[2], txb, txl);

	msg.addr = i2c->addr;
	msg.flags = 0;
	msg.len = 2 + txl;
	msg.buf = hw_priv->txd;

	if (i2c_transfer(adapter, &msg, 1) != 1)
		pr_alert("i2c_transfer() failed\n");
	i2c_chk_regs(&ks->sw, addr, txb, txl);
}

/**
 * i2c_wrreg32 - write 32bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void i2c_wrreg32(struct sw_priv *ks, u32 reg, u32 val)
{
	u8 txb[4];
	int i = 0;
	size_t cnt = 4;

	do {
		txb[i++] = (u8)(val >> (8 * (cnt - 1)));
		cnt--;
	} while (cnt);
	i2c_wrreg(ks, reg, txb, 4);
}

/**
 * i2c_wrreg24 - write 24bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void i2c_wrreg24(struct sw_priv *ks, u32 reg, u32 val)
{
	u8 txb[4];
	int i = 0;
	size_t cnt = 3;

	do {
		txb[i++] = (u8)(val >> (8 * (cnt - 1)));
		cnt--;
	} while (cnt);
	i2c_wrreg(ks, reg, txb, 3);
}

/**
 * i2c_wrreg16 - write 16bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void i2c_wrreg16(struct sw_priv *ks, u32 reg, u32 val)
{
	u8 txb[4];
	int i = 0;
	size_t cnt = 2;

	do {
		txb[i++] = (u8)(val >> (8 * (cnt - 1)));
		cnt--;
	} while (cnt);
	i2c_wrreg(ks, reg, txb, 2);
}

/**
 * i2c_wrreg8 - write 8bit register value to chip
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @val:	The value to write.
 *
 * Issue a write to put the value @val into the register specified in @reg.
 */
static void i2c_wrreg8(struct sw_priv *ks, u32 reg, u32 val)
{
	u8 txb[4];
	int i = 0;
	size_t cnt = 1;

	do {
		txb[i++] = (u8)(val >> (8 * (cnt - 1)));
		cnt--;
	} while (cnt);
	i2c_wrreg(ks, reg, txb, 1);
}

/**
 * i2c_rdreg - issue read register command and return the data
 * @ks:		The switch device structure.
 * @reg:	The register address.
 * @rxb:	The RX buffer to return the result into.
 * @rxl:	The length of data expected.
 *
 * This is the low level read call that issues the necessary i2c message(s)
 * to read data from the register specified in @op.
 */
static void i2c_rdreg(struct sw_priv *ks, u32 addr, void *rxb, size_t rxl)
{
	struct i2c_hw_priv *hw_priv = ks->hw_dev;
	struct i2c_msg msg[2];
	struct i2c_client *i2c = hw_priv->i2cdev;
	struct i2c_adapter *adapter = i2c->adapter;

	if (!mutex_is_locked(&ks->lock))
		pr_alert("R not locked\n");

	hw_priv->txd[0] = (u8)(addr >> 8);
	hw_priv->txd[1] = (u8) addr;

	msg[0].addr = i2c->addr;
	msg[0].flags = 0;
	msg[0].len = 2;
	msg[0].buf = hw_priv->txd;

	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = rxl;
	msg[1].buf = rxb;

	if (i2c_transfer(adapter, msg, 2) != 2)
		pr_alert("i2c_transfer() failed\n");
}

/**
 * i2c_rdreg8 - read 8 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 8bit register from the chip, returning the result.
 */
static u8 i2c_rdreg8(struct sw_priv *ks, u32 reg)
{
	u8 rxb[1];

	i2c_rdreg(ks, reg, rxb, 1);
	return rxb[0];
}

/**
 * i2c_rdreg16 - read 16 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 16bit register from the chip, returning the result.
 */
static u16 i2c_rdreg16(struct sw_priv *ks, u32 reg)
{
	__le16 rx = 0;

	i2c_rdreg(ks, reg, &rx, 2);
	return be16_to_cpu(rx);
}

/**
 * i2c_rdreg24 - read 24 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 24bit register from the chip.
 */
static u32 i2c_rdreg24(struct sw_priv *ks, u32 reg)
{
	__le32 rx = 0;

	i2c_rdreg(ks, reg, &rx, 3);
	return be32_to_cpu(rx);
}

/**
 * i2c_rdreg32 - read 32 bit register from device
 * @ks:		The switch device structure.
 * @reg:	The register address.
 *
 * Read a 32bit register from the chip.
 */
static u32 i2c_rdreg32(struct sw_priv *ks, u32 reg)
{
	__le32 rx = 0;

	i2c_rdreg(ks, reg, &rx, 4);
	return be32_to_cpu(rx);
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

/* For ksz_request used by PTP or MRP driver. */
#include "ksz_req.c"

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

#define KSZSW_REGS_SIZE			0x8000

static struct sw_regs {
	int start;
	int end;
} sw_regs_range[] = {
	{ 0x0000, 0x7FFF },
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

static void sw_lock(struct ksz_sw *sw)
{
	const struct ksz_sw_reg_ops *reg_ops = sw->reg;

	mutex_lock(sw->reglock);
	if (sw->reg != reg_ops) {
printk(KERN_ALERT "%s changed\n", __func__);
		mutex_unlock(sw->reglock);
		sw->reg->lock(sw);
	}
}  /* sw_lock */

static void sw_unlock(struct ksz_sw *sw)
{
	mutex_unlock(sw->reglock);
}  /* sw_unlock */

static int exit_mib_read(struct ksz_sw *sw)
{
	if (sw->intr_using)
		return true;
	return false;
}  /* exit_mib_read */

static u8 sw_r8(struct ksz_sw *sw, unsigned reg)
{
	return HW_R8(sw->dev, reg);
}

static u16 sw_r16(struct ksz_sw *sw, unsigned reg)
{
	return HW_R16(sw->dev, reg);
}

static u32 sw_r24(struct ksz_sw *sw, unsigned reg)
{
	return HW_R24(sw->dev, reg);
}

static u32 sw_r32(struct ksz_sw *sw, unsigned reg)
{
	return HW_R32(sw->dev, reg);
}

static void sw_r(struct ksz_sw *sw, unsigned reg, void *buf, size_t cnt)
{
	i2c_rdreg(sw->dev, reg, buf, cnt);
}

static void sw_w(struct ksz_sw *sw, unsigned reg, void *buf, size_t cnt)
{
	i2c_wrreg(sw->dev, reg, buf, cnt);
}

static void sw_w8(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W8(sw->dev, reg, val);
}

static void sw_w16(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W16(sw->dev, reg, val);
}

static void sw_w24(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W24(sw->dev, reg, val);
}

static void sw_w32(struct ksz_sw *sw, unsigned reg, unsigned val)
{
	HW_W32(sw->dev, reg, val);
}


static void link_update_work(struct work_struct *work);

static void sw_dis_intr(struct ksz_sw *sw);
static void sw_ena_intr(struct ksz_sw *sw);

#define USE_DIFF_PORT_PRIORITY
#include "ksz_sw_9897.c"


#define MAX_I2C_DEVICES		1

static int ksz9897_probe(struct i2c_client *i2c,
	const struct i2c_device_id *i2c_id)
{
	struct i2c_hw_priv *hw_priv;
	struct sw_priv *ks;

	ks = kzalloc(sizeof(struct sw_priv), GFP_KERNEL);
	if (!ks)
		return -ENOMEM;

	ks->hw_dev = kzalloc(sizeof(struct i2c_hw_priv), GFP_KERNEL);
	if (!ks->hw_dev) {
		kfree(ks);
		return -ENOMEM;
	}
	hw_priv = ks->hw_dev;

	hw_priv->i2cdev = i2c;

	ks->dev = &i2c->dev;
	if (i2c->irq <= 0)
		i2c->irq = get_irq(ks, i2c->irq);

	ks->intr_mode = intr_mode ? IRQF_TRIGGER_FALLING :
		IRQF_TRIGGER_LOW;
	ks->irq = i2c->irq;

	return ksz_probe(ks);
}

static int ksz9897_remove(struct i2c_client *i2c)
{
	struct sw_priv *ks = dev_get_drvdata(&i2c->dev);

	return ksz_remove(ks);
}

#define I2C_SWITCH_NAME			"i2c-ksz9897"

/* Please change the I2C address if necessary. */
#define I2C_SWITCH_ADDR			0x5F

/* Please provide a system interrupt number here. */
#define I2C_SWITCH_INTR			-1

static int ksz9897_detect(struct i2c_client *i2c, struct i2c_board_info *info)
{
	strncpy(info->type, I2C_SWITCH_NAME, I2C_NAME_SIZE);
	info->irq = I2C_SWITCH_INTR;
	return 0;
}

static unsigned short i2c_address_list[] = {
	I2C_SWITCH_ADDR,

	I2C_CLIENT_END
};

static const struct i2c_device_id i2c_id[] = {
	{ I2C_SWITCH_NAME, 0 },
	{ },
};

static struct i2c_driver ksz9897_driver = {
	.driver.name	= I2C_SWITCH_NAME,
	.probe		= ksz9897_probe,
	.remove		= ksz9897_remove,
	.id_table	= i2c_id,

	/* Big enough to be accepted in all cases. */
	.class		= 0xffff,
	.detect		= ksz9897_detect,
	.address_list	= i2c_address_list,
};

static int __init ksz9897_init(void)
{
	int ret;

#ifdef DEBUG_MSG
	if (init_dbg())
		return -ENOMEM;
#endif
	ret = i2c_add_driver(&ksz9897_driver);
	if (ret)
		return ret;

	/* Probe not called. */
	if (!sw_device_present) {
		struct i2c_adapter *adap;

		/* Assume I2C bus starts at 0. */
		adap = i2c_get_adapter(0);

		/* I2C master may not be created yet. */
		if (!adap) {
#if !defined(CONFIG_I2C_KSZ9897_MODULE)
			struct i2c_board_info info = {
				.type	= I2C_SWITCH_NAME,
				.addr	= I2C_SWITCH_ADDR,
				.irq	= I2C_SWITCH_INTR,
			};

			ret = i2c_register_board_info(0, &info, 1);
#else
			return -ENODEV;
#endif
		} else
			i2c_put_adapter(adap);
	}
	return ret;
}

static void __exit ksz9897_exit(void)
{
	i2c_del_driver(&ksz9897_driver);
#ifdef DEBUG_MSG
	exit_dbg();
#endif
}

#ifndef CONFIG_KSZ_SWITCH_EMBEDDED
module_init(ksz9897_init);
module_exit(ksz9897_exit);
#endif

module_param(fast_aging, int, 0);
module_param(multi_dev, int, 0);
module_param(stp, int, 0);
module_param(avb, int, 0);
module_param(authen, int, 0);
MODULE_PARM_DESC(fast_aging, "Fast aging");
MODULE_PARM_DESC(multi_dev, "Multiple device interfaces");
MODULE_PARM_DESC(stp, "STP support");
MODULE_PARM_DESC(avb, "AVB support");
MODULE_PARM_DESC(authen, "802.1X Authentication");

#ifdef CONFIG_KSZ_IBA
module_param(iba, int, 0);
MODULE_PARM_DESC(iba, "IBA support");
#endif

module_param(intr_mode, int, 0);
MODULE_PARM_DESC(intr_mode,
	"Configure which interrupt mode to use(0=level low, 1=falling)");

module_param(need_link_up, int, 0);
MODULE_PARM_DESC(need_link_up,
	"Configure whether to always indicate link is up");

module_param(sw_host_port, int, 0);
MODULE_PARM_DESC(sw_host_port,
	"Configure switch host port");

module_param(ports, int, 0);
MODULE_PARM_DESC(ports,
	"Configure number of ports");

module_param(eth1_ports, int, 0);
module_param(eth2_ports, int, 0);
module_param(eth3_ports, int, 0);
module_param(eth4_ports, int, 0);
module_param(eth5_ports, int, 0);
module_param(eth6_ports, int, 0);
MODULE_PARM_DESC(eth1_ports, "Ports to use on device 1.");
MODULE_PARM_DESC(eth2_ports, "Ports to use on device 2.");
MODULE_PARM_DESC(eth3_ports, "Ports to use on device 3.");
MODULE_PARM_DESC(eth4_ports, "Ports to use on device 4.");
MODULE_PARM_DESC(eth5_ports, "Ports to use on device 5.");
MODULE_PARM_DESC(eth6_ports, "Ports to use on device 6.");

module_param(eth1_vlan, int, 0);
module_param(eth2_vlan, int, 0);
module_param(eth3_vlan, int, 0);
module_param(eth4_vlan, int, 0);
module_param(eth5_vlan, int, 0);
module_param(eth6_vlan, int, 0);
MODULE_PARM_DESC(eth1_vlan, "VLAN to use on device 1.");
MODULE_PARM_DESC(eth2_vlan, "VLAN to use on device 2.");
MODULE_PARM_DESC(eth3_vlan, "VLAN to use on device 3.");
MODULE_PARM_DESC(eth4_vlan, "VLAN to use on device 4.");
MODULE_PARM_DESC(eth5_vlan, "VLAN to use on device 5.");
MODULE_PARM_DESC(eth6_vlan, "VLAN to use on device 6.");

module_param(eth1_proto, charp, 0);
module_param(eth2_proto, charp, 0);
module_param(eth3_proto, charp, 0);
module_param(eth4_proto, charp, 0);
module_param(eth5_proto, charp, 0);
module_param(eth6_proto, charp, 0);
MODULE_PARM_DESC(eth1_proto, "Protocol to use on device 1.");
MODULE_PARM_DESC(eth2_proto, "Protocol to use on device 2.");
MODULE_PARM_DESC(eth3_proto, "Protocol to use on device 3.");
MODULE_PARM_DESC(eth4_proto, "Protocol to use on device 4.");
MODULE_PARM_DESC(eth5_proto, "Protocol to use on device 5.");
MODULE_PARM_DESC(eth6_proto, "Protocol to use on device 6.");

#ifndef CONFIG_KSZ_SWITCH_EMBEDDED
MODULE_DESCRIPTION("Microchip KSZ9897 I2C Switch Driver");
MODULE_AUTHOR("Tristram Ha <Tristram.Ha@microchip.com>");
MODULE_LICENSE("GPL");

MODULE_ALIAS("i2c:ksz9897");
#endif
