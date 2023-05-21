cmake_minimum_required(VERSION 3.5)

project(SAPWF)

# Create a sources variable with a link to all cpp files to compile
set (feature_sou
    src/feature/main_feature.cpp
    src/feature/TCP_flow.cpp
)

# Add an executable with the above sources
add_executable(feature ${feature_sou}) 

# Set the directories that should be included in the build command for this target
# when running g++ these will be included as -I/directory/path/
target_include_directories(feature PRIVATE ${PROJECT_SOURCE_DIR}/include)

IF (WIN32) 
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a )
ELSEIF (UNIX)
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/linux/libconfig++.so )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/linux/libFlow2SE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/linux/libPcapSE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/linux/libPacketSE.a )
    target_link_libraries(feature ${PROJECT_SOURCE_DIR}/lib/linux/libHashSE.a )
ELSEIF ()
ENDIF ()
