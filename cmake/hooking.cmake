include(FetchContent)

FetchContent_Declare(
    hooking
    GIT_REPOSITORY https://github.com/ThirteenAG/Hooking.Patterns.git
    GIT_TAG        62d4ff80e4a9c587f75bc6eaf6325e2b140bde28
    GIT_PROGRESS   TRUE
)
FetchContent_GetProperties(hooking)
if(NOT hooking_POPULATED)
    FetchContent_Populate(hooking)

    file(GLOB SRC_HOOKING
        "${hooking_SOURCE_DIR}/*.cpp"
    )

    add_library(hooking STATIC ${SRC_HOOKING} )
    source_group(TREE ${hooking_SOURCE_DIR} PREFIX "hooking" FILES ${SRC_HOOKING})
    target_include_directories(hooking PRIVATE
        "${hooking_SOURCE_DIR}"
    )
endif()
set_property(TARGET hooking PROPERTY CXX_STANDARD 20)
