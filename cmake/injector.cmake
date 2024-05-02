include(FetchContent)

FetchContent_Declare(
    injector
    GIT_REPOSITORY https://github.com/ThirteenAG/injector.git
    GIT_TAG        cee3a246f93a7ebdb6afdc61160dadbd51ea9dce
    GIT_PROGRESS   TRUE
)
FetchContent_GetProperties(injector)
if(NOT injector_POPULATED)
    FetchContent_Populate(injector)

    file(GLOB SRC_INJECTOR
        "${injector_SOURCE_DIR}/safetyhook/*.cpp"
        "${injector_SOURCE_DIR}/safetyhook/*.c"
    )

    add_library(injector STATIC ${SRC_INJECTOR} )
    source_group(TREE ${injector_SOURCE_DIR} PREFIX "injector" FILES ${SRC_INJECTOR})
    target_include_directories(injector PRIVATE
        "${injector_SOURCE_DIR}/safetyhook"
        "${injector_SOURCE_DIR}/include"
    )
endif()
set_property(TARGET injector PROPERTY CXX_STANDARD 23)
