#ifndef TLS_SMP_FLOW_H
#define TLS_SMP_FLOW_H

#include "_lib.h/libFlow2SE.h"
#include "_lib.h/libTlsFragSE.h"
#include <vector>

//==============================================================================
//==============================================================================
//==============================================================================

class TCP_flow_creator: public IFlow2ObjectCreator
{
public:
    TCP_flow_creator(packet_statistics_object_type type, std::string fname, std::string output, 
                    int tls_threshold, double prop_threshold, int min_frequ);
    ~TCP_flow_creator();
public:
    IFlow2Object* create_Object(uint8_t* buf, int len);
    int filter_packet(CPacket* lppck);
public:    
    std::string getName() {return str_name;}
    packet_statistics_object_type getStatType() {return pso_type;}
    bool isSave() {return false;}

    std::string get_output() {return str_output;}
    int get_TLS_threshold() {return tls_thre;}
    double get_prop_threshold() {return prop_thre;}
    int get_min_frequent() {return min_frequent;}
public:
    void add_feature(int len);
    void save_merge_feature(std::string fname);
private:
    bool have_merge_featrue();
private:
    packet_statistics_object_type pso_type;

    std::string str_name, str_output;

    int tls_thre;
    double prop_thre;
    int min_frequent;

    uint32_t* arr_length_counter;    
};

//==============================================================================
//==============================================================================
//==============================================================================

class TCP_flow: public IFlow2Object
{
public:
    TCP_flow(uint8_t* buf, int len, TCP_flow_creator* lpFOC);
    ~TCP_flow();
public:
    bool checkObject();
    bool isSameObject(uint8_t* buf, int len);
    bool addPacket(CPacket* lppck, bool bSou);
    bool saveObject(FILE* fp, uint64_t cntP, bool bFin);
public:
    uint32_t getPckCnt() {return cntPck;}
    void incPckCnt() {cntPck++;}
private:
    uint32_t cntPck;
private:
    TCP_flow_creator* lpCreator;
    uint8_t* bufKey;
    int lenKey;
    uint32_t selfHash;
private:
    int find_TLS_flag(uint8_t* buf, int len, int &pos);
    void add_TLS_frag(int len);
private:
    int i_check_TLS;
    int total_TLS;
    uint32_t* arr_length_counter;
};

#endif
