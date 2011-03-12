SET( NAME faes )

SET( SOURCES
     CPU.cpp )

### Build and link ####

ADD_LIBRARY( ${NAME} ${SOURCES} ) 
