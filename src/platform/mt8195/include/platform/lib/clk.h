// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2021 Mediatek
//
// Author: YC Hung <yc.hung@mediatek.com>

#ifdef __SOF_LIB_CLK_H__

#ifndef __PLATFORM_LIB_CLK_H__
#define __PLATFORM_LIB_CLK_H__

#include <stdint.h>

struct sof;

#define CLK_CPU(x) (x)

#define CPU_DEFAULT_IDX 4

#define CLK_DEFAULT_CPU_HZ 720000000
#define CLK_MAX_CPU_HZ 720000000

#define NUM_CLOCKS 1

#define NUM_CPU_FREQ 5

void platform_clock_init(struct sof *sof);

#define REG_TOPCKGEN_BASE		0x10000000
#define REG_APMIXDSYS_BASE		0x1000C000
#define REG_SCP_BASE			0x10700000

/* dsp clock */
#define DSPPLL_CON0		(REG_APMIXDSYS_BASE + 0x7E0)
#define DSPPLL_CON1		(REG_APMIXDSYS_BASE + 0x7E4)
#define DSPPLL_CON2		(REG_APMIXDSYS_BASE + 0x7E8)
#define DSPPLL_CON3		(REG_APMIXDSYS_BASE + 0x7EC)
#define DSPPLL_CON4		(REG_APMIXDSYS_BASE + 0x7F0)

#define PLL_BASE_EN		BIT(0)
#define PLL_PWR_ON		BIT(0)
#define PLL_ISO_EN		BIT(1)
#define PLL_EN			BIT(9)

#define CLK_MODE		(REG_TOPCKGEN_BASE + 0x0)
#define CLK_CFG_UPDATE0		(REG_TOPCKGEN_BASE + 0x4)
#define CLK_CFG_UPDATE1		(REG_TOPCKGEN_BASE + 0x8)
#define CLK_CFG_UPDATE2		(REG_TOPCKGEN_BASE + 0xC)
#define CLK_CFG_UPDATE3		(REG_TOPCKGEN_BASE + 0x10)

#define CLK_CFG_22		(REG_TOPCKGEN_BASE + 0x128)
#define CLK_CFG_22_SET		(REG_TOPCKGEN_BASE + 0x12C)
#define CLK_CFG_22_CLR		(REG_TOPCKGEN_BASE + 0x130)

#define CLK_CFG_28		(REG_TOPCKGEN_BASE + 0x170)
#define CLK_CFG_28_SET		(REG_TOPCKGEN_BASE + 0x174)
#define CLK_CFG_28_CLR		(REG_TOPCKGEN_BASE + 0x178)

/* CLK_CFG_UPDATE2 */
#define CLK_UPDATE_ADSP_CK		24

/* CLK_CFG_UPDATE3 */
#define CLK_UPDATE_AUDIO_LOCAL_BUS_CK	18

/* CLK_CFG_22[3:0] hf_fadsp_ck_sel clksrc. */
#define CLK_ADSP_SEL_26M		0
#define CLK_ADSP_SEL_26M_D_2		1
#define CLK_ADSP_SEL_MAINPLL_D_6	2
#define CLK_ADSP_SEL_MAINPLL_D_5_D_2	3
#define CLK_ADSP_SEL_MAINPLL_D_4_D_4	4
#define CLK_ADSP_SEL_UNIVPLL_D_4	5
#define CLK_ADSP_SEL_UNIVPLL_D_6	6
#define CLK_ADSP_SEL_ULPOSC		7
#define CLK_ADSP_SEL_ADSPPLL		8
#define CLK_ADSP_SEL_ADSPPLL_D_2	9
#define CLK_ADSP_SEL_ADSPPLL_D_4	10
#define CLK_ADSP_SEL_ADSPPLL_D_8	11

/* CLK_CFG_28[19:16] hf_faudio_local_bus_ck_sel clksrc. */
#define CLK_AUDIO_LOCAL_BUS_SEL_26M		0
#define CLK_AUDIO_LOCAL_BUS_SEL_26M_D_2		1
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_4_D_4	2
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_7_D_2	3
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_4_D_2	4
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_5_D_2	5
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_6_D_2	6
#define CLK_AUDIO_LOCAL_BUS_SEL_MAINPLL_D_7	7
#define CLK_AUDIO_LOCAL_BUS_SEL_UNIVPLL_D_6	8
#define CLK_AUDIO_LOCAL_BUS_SEL_ULPOSC		9
#define CLK_AUDIO_LOCAL_BUS_SEL_ULPOSC_D_4	10
#define CLK_AUDIO_LOCAL_BUS_SEL_ULPOSC_D_2	11

#define AUDIODSP_CK_CG			(REG_SCP_BASE + 0x20180)
#define RG_AUDIODSP_SW_CG		0

enum mux_id_t {
	MUX_CLK_ADSP_SEL = 0,
	MUX_CLK_AUDIO_LOCAL_BUS_SEL,
	HIFI4DSP_MUX_NUM,
};

enum DSP_HW_DSP_CLK {
	DSP_CLK_13M = 0,
	DSP_CLK_26M,
	DSP_CLK_PLL_370M,
	DSP_CLK_PLL_540M,
	DSP_CLK_PLL_720M,
};
#endif /* __PLATFORM_LIB_CLK_H__ */

#else

#error "This file shouldn't be included from outside of sof/lib/clk.h"

#endif /* __SOF_LIB_CLK_H__ */
