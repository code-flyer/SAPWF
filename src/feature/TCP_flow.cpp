#include <iostream>

#include "_lib.h/libHashSE.h"
#include "feature/TCP_flow.h"

using namespace std;

const int size_16K_TLS = 1024*16 +50;

TCP_flow_creator::TCP_flow_creator(packet_statistics_object_type type, string fn, string output, 
                int tls_threshold, double prop_threshold, int min_frequ)
{
     pso_type = type;
     str_name = fn;
     str_output = output;
     tls_thre = tls_threshold;
     prop_thre = prop_threshold;
     min_frequent = min_frequ;

    arr_length_counter = (uint32_t*)calloc(size_16K_TLS, sizeof(uint32_t));
    for(int i=0; i<size_16K_TLS; i++)
        arr_length_counter[i] = 0;
}

TCP_flow_creator::~TCP_flow_creator()
{
    if(arr_length_counter)
        free(arr_length_counter);
}

IFlow2Object* TCP_flow_creator::create_Object(uint8_t* buf, int len)
{
    TCP_flow* lpFlow = new TCP_flow(buf, len, this);
    return lpFlow;
}

int TCP_flow_creator::filter_packet(CPacket* lppck)
{
    int iout = 0;
    if(lppck->getSrcPort() == 443)
        iout = 1;
    return iout;
}

void TCP_flow_creator::add_feature(int len)
{
    if(len >= 0 && len < size_16K_TLS)
        arr_length_counter [len] = 1;
}

void TCP_flow_creator::save_merge_feature(std::string fname)
{
    if(have_merge_featrue())
    {
        FILE *fp = fopen(fname.c_str(), "at");
        if(fp)
        {
            fprintf(fp, "%s,", str_name.c_str());
            
            for(int i=0; i<size_16K_TLS; i++)
            {
                if(arr_length_counter[i] > 0)
                {
                    fprintf(fp, "%d,", i);
                }
            }
            fprintf(fp, "\n");
            fclose(fp);
        }
    }
}

bool TCP_flow_creator::have_merge_featrue()
{
    bool bout = false;

    for(int i=0; i<size_16K_TLS; i++)
    {
        if(arr_length_counter[i] > 0)
        {
            bout = true;
            break;
        }
    }
    return bout;
}

//==============================================================================
//==============================================================================
//==============================================================================

TCP_flow::TCP_flow(uint8_t* buf, int len, TCP_flow_creator* lpFOC)
{
    cntPck = 0;
    lpCreator = lpFOC;
    if(len>0)
    {
        lenKey = len;
        bufKey = (uint8_t*)calloc(lenKey, sizeof(uint8_t));
        if(bufKey)
        {
            memcpy(bufKey, buf, len);
           	selfHash = CHashTools::HashBuffer(bufKey, lenKey, 32);
        }
    }

    i_check_TLS = 0;
    total_TLS = 0;
    arr_length_counter = (uint32_t*)calloc(size_16K_TLS, sizeof(uint32_t));
    for(int i=0; i<size_16K_TLS; i++)
        arr_length_counter[i] = 0;
}

TCP_flow::~TCP_flow()
{
    if(bufKey)
        free(bufKey);
    if(arr_length_counter)
        delete arr_length_counter;
}

bool TCP_flow::checkObject()
{
    if(lenKey>0 && bufKey)
        return true;
    else
        return false;
}

bool TCP_flow::isSameObject(uint8_t* buf, int len)
{
    bool bout = false;

    if(lenKey == len)
    {
        if(memcmp(bufKey, buf, len)==0)
            bout = true;
    }
    return bout;
}

bool TCP_flow::addPacket(CPacket* lppck, bool bSou)
{
    int len;
    uint8_t *buffer = lppck->getPacketPayload(len);

    if(i_check_TLS==0 || i_check_TLS==1)
    {
        int pos = 0;
        int len_TLS = find_TLS_flag(buffer, len, pos);
        while(len_TLS > 0)
        {
            add_TLS_frag(len_TLS);
            len_TLS = find_TLS_flag(buffer, len, pos);
            if(i_check_TLS == 0)    
                i_check_TLS = 1;
        }
        if(i_check_TLS == 0 && cntPck > 100)
            i_check_TLS = 2;
    }

    return true;
}

bool TCP_flow::saveObject(FILE* fp, uint64_t cntP, bool bFin)
{
    if(i_check_TLS==1 && total_TLS >= lpCreator->get_TLS_threshold())
    {
        string fn = lpCreator->get_output();

        if(fn.length() > 0)
        {
            FILE* fp = fopen(fn.c_str(), "at");
            if(fp)
            {
                char buf_IPP[UINT8_MAX];
                double cnt = lpCreator->get_prop_threshold() * total_TLS ;
                if(cnt < lpCreator->get_min_frequent())
                    cnt  = lpCreator->get_min_frequent();
                bool bSave = false;
                for(int i=0; i<size_16K_TLS; i++)
                {
                    if(arr_length_counter[i] >= cnt && i != 16406)
                    {
                        bSave = true;
                        break;
                    }
                }
                if(bSave)
                {
                    CPacketTools::getStr_IPport_from_hashbuf(bufKey, lenKey, buf_IPP);
                    fprintf(fp, "%s,%s%u,%d,%u,,", lpCreator->getName().c_str(), buf_IPP, selfHash, total_TLS, cntPck);
                    for(int i=0; i<size_16K_TLS; i++)
                    {
                        if(arr_length_counter[i] >= cnt)
                        {
                            double rate = (double)arr_length_counter[i]/total_TLS;
                            fprintf(fp, "%d,%.4f,,", i, rate);
                            lpCreator->add_feature(i);
                        }
                    }
                    fprintf(fp, "\n");
                }
                fclose(fp);
            }
        }
    }
    return true;
}

int TCP_flow::find_TLS_flag(uint8_t* buf, int len, int &pos)
{
    int iout = 0;

    for(int i=pos; i<len-5; i++)
    {
        if(buf[i] == 0x17)
        {
            if(buf[i+1] == 3 && buf[i+2] == 3)
            {
                iout = buf[i+3] * 256 + buf[i+4] + 5;
                if(iout >= size_16K_TLS)
                    iout = 0;
                else
                    pos = i + 5;
                break;
            }
        }
    }

    return iout;
}

void TCP_flow::add_TLS_frag(int len)
{
    if(len>0 && len<size_16K_TLS)
    {
        arr_length_counter[len] ++;
        total_TLS ++;
    }
}
