SET( NAME faes )

SET( SOURCES
     Common.cpp
     CPU.cpp 
     Key.cpp
     AES.cpp )

ADD_LIBRARY( ${NAME} ${SOURCES} ) 
