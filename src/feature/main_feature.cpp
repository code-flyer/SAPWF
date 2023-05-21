/**
MIT License

Copyright (c) 2021 XXXX, hwu(hwu@seu.edu.cn) 

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

#include <iostream>
#include <cstring>
#include <time.h>
#include <vector>
#include <bits/stdc++.h>

#include "_lib.h/libPcapSE.h"
#include "winlin/winlinux.h"
#include "_lib.h/libconfig.h++"
#include "feature/TCP_flow.h"

using namespace std;  
using namespace libconfig;

int begin_pos;

int calRatio(int num)
{
    int iout;

    switch (num)
    {
    case 0:
        iout = 1;
        break;
    case 1:
        iout = 8;
        break;
    case 2:
        iout = 16;
        break;
    case 3:
        iout = 32;
        break;
    case 4:
        iout = 64;
        break;
    case 5:
        iout = 128;
        break;
    case 6:
        iout = 256;
        break;
    case 7:
        iout = 512;
        break;
    case 8:
        iout = 1024;
        break;
    case 9:
        iout = 2048;
        break;
    case 10:
        iout = 4096;
        break;
    case 11:
        iout = 8192;
        break;
    case 12:
        iout = 16384;
        break;
    case 13:
        iout = 32768;
        break;
    case 14:
        iout = 65536;
        break;
    case 20:
        iout = 2;
        break;
    case 21:
        iout = 4;
        break;
    default:
        iout = 256;
        break;
    }
    return iout;
}

void stat_sampling(string fname, string output, string fn_merge, int ratio, int tls, double prop, int min_frequ)
{
    packet_statistics_object_type typeS = pso_IPPort;
    IFlow2Stat* lpFS = CFlow2StatCreator::create_flow2_stat(fname.c_str(), 22, 2);
    TCP_flow_creator* lpFC = new TCP_flow_creator(typeS, fname.c_str(), output, tls, prop, min_frequ);
    if(lpFS && lpFC)
    {
        lpFS->setParameter(typeS, 1, psm_filter, true);
        lpFS->setCreator(lpFC);
        if(lpFS->isChecked())
        {
            lpFS->iterSamplePcap(ratio, begin_pos);
            lpFC->save_merge_feature(fn_merge);
        }
        delete lpFC;
        delete lpFS;
    }
    else
        cout << "pcap file " << fname << " open error!" << endl;
}

void findPath(string strpath, int ratio, int tls_thre, double prop_thre, int min_frequ)
{
    if(strpath.length()>0)
    {
        string output = strpath + "0_TLS_sampling.rate_" + to_string(ratio) + ".TLS_" + to_string(tls_thre) + ".csv";
        FILE* fp = fopen(output.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "file,protocol,IP,port,hash,Num_TLS,sample_pck,,length,proportion\n");
            fclose(fp);
        }
        else
            cout << output << " error open!!!" << endl;

        string fn_merge = strpath + "0_TLS_sampling.merge.rate_" + to_string(ratio) + ".TLS_" + to_string(tls_thre) + ".csv";
        fp = fopen(fn_merge.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "file,...\n");
            fclose(fp);
        }
        else
            cout << output << " error open!!!" << endl;

        vector<string> vctFN;
        if(iterPathPcaps(strpath, &vctFN))
        {
            for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
            {
                string strFN = *iter; 
                if(strFN.length()>0)
                {
                    stat_sampling(strFN.c_str(), output, fn_merge, ratio, tls_thre, prop_thre, min_frequ);
                }
            }
        }
    }
}

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE);
    }    

    try
    {
        //path
        string path = cfg.lookup("TLS_sampling_path");    
        cout << "path name: " << path << endl;
      
        int tls_th, rno, ratio, seed, min_frequ;
        double prop_th;

        cfg.lookupValue("SMP_ratio", rno);
        cout << "Sampling rate no: " << rno << endl;
        ratio = calRatio(rno);
        cout << "Sampling rate:1/" << ratio << endl;
        cfg.lookupValue("SMP_random_seed", seed);
        cout << "random seed: " << seed << endl;
        srand(seed);
        begin_pos = rand() % ratio;

        cfg.lookupValue("SMP_TLS_threshold", tls_th);
        cout << "TLS fragment threshold:" << tls_th << endl;
        cfg.lookupValue("SMP_prop_threshold", prop_th);
        cout << "probability threshold:" << prop_th << endl;
        cfg.lookupValue("SMP_min_frequent", min_frequ);
        cout << "min frequent TLS block:" << min_frequ << endl;

        findPath(path, ratio, tls_th, prop_th, min_frequ);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }

    return 0;
}