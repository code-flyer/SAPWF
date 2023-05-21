#ifndef WIN_LINUX_H
#define WIN_LINUX_H

#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <sys/types.h>
    #include <dirent.h>
#endif
#include <bits/stdc++.h>
#include <cstring>
#include <vector>

bool checkPcapFilename(char* filename)
{
    bool bout = false;

    std::string fnn = filename;
    if(fnn.size()>5)
    {
        std::string sub = fnn.substr(fnn.size()-5,5);
        std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
        if(sub==".pcap")
            bout = true;
    }
    if(!bout && fnn.size()>7)
    {
        std::string sub = fnn.substr(fnn.size()-7,7);
        std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
        if(sub==".pcapng")
            bout = true;
    }

    return bout;
}

bool iterPathPcaps(std::string strPath, std::vector<std::string>* lpFN)
{
    bool bout = false;

    if(strPath.length()>0)
    {
        char fname[UINT8_MAX];
#ifdef _WIN32
        _finddata_t file;
        intptr_t HANDLE;

        sprintf(fname, "%s*.*", strPath.c_str());
        HANDLE = _findfirst(fname, &file);
        if(HANDLE >= 0)
        {
            do
            {
                if(checkPcapFilename(file.name))
                {
                    std::string pathf = strPath + file.name;
                    lpFN->push_back(pathf);
                    bout = true;
                }
            } while (_findnext(HANDLE, &file)==0);
            _findclose(HANDLE);
        }        
        else
            std::cerr << strPath << " path error." << std::endl;
#elif  __linux__
        DIR * dirp = NULL; 
        struct dirent * pDirent= NULL;

    	dirp = opendir(strPath.c_str());
    	if (NULL == dirp)
            std::cerr << strPath << " path error." << std::endl;
        else
        {
        	while (NULL != (pDirent = readdir(dirp)))
        	{
                if(pDirent->d_type == DT_REG)
                {
                    if(checkPcapFilename(pDirent->d_name))
                    {
                        std::string pathf = strPath + pDirent->d_name;
                        lpFN->push_back(pathf);
                        bout = true;
                    }
                }
            }
        }
        closedir(dirp);
#endif          
    }
    return bout;
}

bool iterPathPcaps_full(std::string strPath, std::vector<std::string>* lpFN)
{
    bool bout = false;
    std::string pathf;

    if(strPath.length()>0)
    {
        char fname[UINT8_MAX];
#ifdef _WIN32
        _finddata_t file;
        intptr_t HANDLE;

        sprintf(fname, "%s*.*", strPath.c_str());
        HANDLE = _findfirst(fname, &file);
        if(HANDLE >= 0)
        {
            do
            {
                if(file.attrib&_A_SUBDIR)
                {
                    if( strcmp(file.name, ".")!=0 && strcmp(file.name, "..")!=0 )
                    {
                        pathf = strPath + file.name + "/";
                        if(iterPathPcaps_full(pathf, lpFN))
                            bout = true;
                    }
                }
                else if(checkPcapFilename(file.name))
                {
                    pathf = strPath + file.name;
                    lpFN->push_back(pathf);
                    bout = true;
                }
            } while (_findnext(HANDLE, &file)==0);
            _findclose(HANDLE);
        }        
        else
            std::cerr << strPath << " path error." << std::endl;
#elif  __linux__
        DIR * dirp = NULL; 
        struct dirent * pDirent= NULL;

    	dirp = opendir(strPath.c_str());
    	if (NULL == dirp)
            std::cerr << strPath << " path error." << std::endl;
        else
        {
        	while (NULL != (pDirent = readdir(dirp)))
        	{
                if(pDirent->d_type == DT_REG)
                {
                    if(checkPcapFilename(pDirent->d_name))
                    {
                        std::string pathf = strPath + pDirent->d_name;
                        lpFN->push_back(pathf);
                        bout = true;
                    }
                }
            }
        }
        closedir(dirp);
#endif          
    }

    if(lpFN->size()>0)
        bout = true;
    return bout;
}

bool filter_iterate_path_file(std::string strPath, std::vector<std::string>* lpFN, std::string str_filter)
{
    bool bout = false;
    std::string pathf;

    if(strPath.length()>0)
    {
        char fname[UINT8_MAX];
#ifdef _WIN32
        _finddata_t file;
        intptr_t HANDLE;

        sprintf(fname, "%s*.*", strPath.c_str());
        HANDLE = _findfirst(fname, &file);
        if(HANDLE >= 0)
        {
            do
            {
                if(file.attrib&_A_SUBDIR)
                {
                    if( strcmp(file.name, ".")!=0 && strcmp(file.name, "..")!=0 )
                    {
                        pathf = strPath + file.name + "/";
                        if(filter_iterate_path_file(pathf, lpFN, str_filter))
                            bout = true;
                    }
                }
                else
                {
                    if(strstr(file.name, str_filter.c_str()) != NULL)
                    {
                        pathf = strPath + file.name;
                        lpFN->push_back(pathf);
                        bout = true;
                    }
                }
            } while (_findnext(HANDLE, &file)==0);
            _findclose(HANDLE);
        }        
        else
            std::cerr << strPath << " path error." << std::endl;
#elif  __linux__
        DIR * dirp = NULL; 
        struct dirent * pDirent= NULL;

    	dirp = opendir(strPath.c_str());
    	if (NULL == dirp)
            std::cerr << strPath << " path error." << std::endl;
        else
        {
        	while (NULL != (pDirent = readdir(dirp)))
        	{
                if(pDirent->d_type == DT_REG)
                {
                    std::string pathf = strPath + pDirent->d_name;
                    lpFN->push_back(pathf);
                    bout = true;
                }
            }
        }
        closedir(dirp);
#endif          
    }
    return bout;    
}

bool iterPathFiles(std::string strPath, std::vector<std::string>* lpFN)
{
    bool bout = false;

    if(strPath.length()>0)
    {
        char fname[UINT8_MAX];
#ifdef _WIN32
        _finddata_t file;
        intptr_t HANDLE;

        sprintf(fname, "%s*.*", strPath.c_str());
        HANDLE = _findfirst(fname, &file);
        if(HANDLE >= 0)
        {
            do
            {
                std::string pathf = strPath + file.name;
                lpFN->push_back(pathf);
                bout = true;
            } while (_findnext(HANDLE, &file)==0);
            _findclose(HANDLE);
        }        
        else
            std::cerr << strPath << " path error." << std::endl;
#elif  __linux__
        DIR * dirp = NULL; 
        struct dirent * pDirent= NULL;

    	dirp = opendir(strPath.c_str());
    	if (NULL == dirp)
            std::cerr << strPath << " path error." << std::endl;
        else
        {
        	while (NULL != (pDirent = readdir(dirp)))
        	{
                if(pDirent->d_type == DT_REG)
                {
                    std::string pathf = strPath + pDirent->d_name;
                    lpFN->push_back(pathf);
                    bout = true;
                }
            }
        }
        closedir(dirp);
#endif          
    }
    return bout;
}



#endif