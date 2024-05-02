include(FetchContent)

FetchContent_Declare(
    mini
    GIT_REPOSITORY https://github.com/metayeti/mINI.git
    GIT_TAG        0.9.15
    GIT_PROGRESS   TRUE
)
FetchContent_GetProperties(mini)
if(NOT mini_POPULATED)
    FetchContent_Populate(mini)
endif()
