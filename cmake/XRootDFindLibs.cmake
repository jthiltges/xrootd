#-------------------------------------------------------------------------------
# Find the required libraries
#-------------------------------------------------------------------------------
find_package( ZLIB REQUIRED)

if( ENABLE_READLINE )
  find_package( Readline )
  if( READLINE_FOUND )
    add_definitions( -DHAVE_READLINE )
  else()
    set( READLINE_LIBRARY "" )
    set( NCURSES_LIBRARY "" )
  endif()
endif()

if( ZLIB_FOUND )
  add_definitions( -DHAVE_LIBZ )
endif()

if( ENABLE_CRYPTO )
  find_package( OpenSSL )
  if( OPENSSL_FOUND )
    add_definitions( -DHAVE_XRDCRYPTO )
    add_definitions( -DHAVE_SSL )
    set( BUILD_CRYPTO TRUE )
  else()
    set( BUILD_CRYPTO FALSE )
  endif()
endif()

if( ENABLE_KRB5 )
  find_package( Kerberos5 )
  if( KERBEROS5_FOUND )
    set( BUILD_KRB5 TRUE )
  else()
    set( BUILD_KRB5 FALSE )
  endif()
endif()

# mac fuse not supported
if( ENABLE_FUSE AND Linux )
  find_package( fuse )
  if( FUSE_FOUND )
    add_definitions( -DHAVE_FUSE )
    set( BUILD_FUSE TRUE )
  else()
    set( BUILD_FUSE FALSE )
  endif()
endif()

if( ENABLE_LIBEVENT )
  find_package( LibEvent )
  if( LIBEVENT_FOUND )
    find_package( LibEventPthreads REQUIRED )
    add_definitions( -DHAVE_LIBEVENT )
    set( BUILD_LIBEVENT TRUE )
  else()
    set( BUILD_LIBEVENT FALSE )
    set( LIBEVENT_LIB "" )
    set( LIBEVENTPTHREADS_LIB "" )
    set( LIBEVENT_INCLUDE_DIR "" )
  endif()
endif()

if( ENABLE_TESTS )
  find_package( CPPUnit )
  if( CPPUNIT_FOUND )
    set( BUILD_TESTS TRUE )
  else()
    set( BUILD_TESTS FALSE )
  endif()
endif()

if( ENABLE_HTTP )
  if( OPENSSL_FOUND AND BUILD_CRYPTO )
    set( BUILD_HTTP TRUE )
  else()
    set( BUILD_HTTP FALSE )
  endif()
endif()
