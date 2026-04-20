set(install_prefix "${install_prefix}")
set(binary_dir "${binary_dir}")

set(spec_file
    "${binary_dir}/_deps/ghidrasource-src/Ghidra/Processors/PowerPC/data/languages/ppc_32_e200_be.slaspec")
set(out_dir
    "${install_prefix}/share/sleigh/specfiles/Ghidra/Processors/PowerPC/data/languages")
set(out_file "${out_dir}/ppc_32_e200_be.sla")
set(log_dir "${binary_dir}/sleighspecs/spec_build_logs")
set(log_file "${log_dir}/ppc_32_e200_be.sla.log")

if(NOT EXISTS "${spec_file}")
    message(FATAL_ERROR "Missing ppc_32_e200_be.slaspec: ${spec_file}")
endif()

find_program(sleigh_compiler NAMES sleigh sleigh.exe
    PATHS "${install_prefix}/bin"
    NO_DEFAULT_PATH
    REQUIRED)

get_filename_component(spec_dir "${spec_file}" DIRECTORY)
file(MAKE_DIRECTORY "${out_dir}")
file(MAKE_DIRECTORY "${log_dir}")

execute_process(
    COMMAND "${sleigh_compiler}" "${spec_file}" "${out_file}"
    WORKING_DIRECTORY "${spec_dir}"
    RESULT_VARIABLE sleigh_result
    OUTPUT_FILE "${log_file}"
    ERROR_FILE "${log_file}"
)

if(NOT sleigh_result EQUAL 0)
    message(FATAL_ERROR
        "Failed to compile ppc_32_e200_be.sla with ${sleigh_compiler}. See ${log_file}")
endif()
