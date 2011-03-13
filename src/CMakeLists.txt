SET( NAME faes )

SET( SOURCES
     CPU.cpp 
     AES.cpp )

### Build and link ####

ADD_LIBRARY( ${NAME} ${SOURCES} ) 
