# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\vAlerainArk_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\vAlerainArk_autogen.dir\\ParseCache.txt"
  "vAlerainArk_autogen"
  )
endif()
