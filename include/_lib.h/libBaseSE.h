/**
MIT License

Copyright (c) 2021 hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * @file libBaseSE.h (https://www.seu.edu.cn/)
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief Basic settings 基础设定
 * @version 0.1
 * @date 2021-11-07
 */

#ifndef LIB_BASE_SE_H
#define LIB_BASE_SE_H

enum packet_statistics_object_type{pso_IPPort = 0, pso_IPPortPair, 
                                   pso_IP, pso_IPPair, 
                                   pso_MACSubnet, pso_MACSubnetPair, 
                                   pso_MAC, pso_MACPair, 
                                   pso_IPMAC, 
                                   pso_MACSubnetB, pso_MACSubnetBPair,
                                   pso_IP_noprot, pso_IPPair_noprot,
                                   pso_IP_subnetB, pso_IP_subnetC,
                                   pso_subnetB_IP, pso_subnetC_IP, 
                                   pso_IP_A_port_B,
                                   pso_SelfDefine};
enum FeatureType{feaFPck=0, feaBPck, 
                 feaFRange, feaBRange, 
                 feaFIPPortHash, feaBIPPortHash, feaFIPHash, feaBIPHash, feaFPortHash, feaBPortHash, feaIPPortPairHash, 
                 feaFLenSum, feaBLenSum, feaFLenSumSqu, feaBLenSumSqu, 
                 feaFPckSpd, feaBPckSpd, feaFPayloadSpd, feaBPayloadSpd, 
                 feaFIPPortHash8, feaBIPPortHash8, feaFIPHash8, feaBIPHash8, feaFPortHash8, feaBPortHash8, feaIPPortPairHash8, 
                 feaFTCP_SYN_and_ACK=48, feaBTCP_SYN_and_ACK, feaFTCP_RWND, feaBTCP_RWND,
                 feaFTCPPSHSYN=52, feaBTCPPSHSYN, feaFTCPSYN, feaBTCPSYN, feaFTCPSACK, feaBTCPSACK, feaTCPTimestamp
                 };

/**
 * @brief statistics method
 * psm_Unique --- Sou, Dst 键值先排序再统计，(五元组统计时会统计到一个键值中)
 * psm_SouDstDouble --- Sou,Dst forward 统计一次， Dst,Sou backward再统计一次 (五元组统计时会统计到两个键值中)
 * psm_filter --- 自己做过滤
 * psm_SD_forward --- Sou,Dst forward 统计一次
 * psm_SD_backward --- Sou,Dst backward 统计一次
 */
enum packet_statistics_method{psm_Unique=0, psm_SouDstSingle, psm_SouDstDouble, psm_filter, psm_SD_forward, psm_SD_backward};

enum direction_statistics{ds_bidirectional=0, ds_forward, ds_backward};
#endif
