add_executable(aleth-key KeyAux.h main.cpp)
target_link_libraries(aleth-key PRIVATE ethcore devcore Boost::program_options Boost::chrono)
install(TARGETS aleth-key EXPORT alethTargets DESTINATION bin)
