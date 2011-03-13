SET( NAME faes )

SET( SOURCES
     Common.cpp
     CPU.cpp 
     AES.cpp )

ADD_LIBRARY( ${NAME} ${SOURCES} ) 
