project('liblorawan', 'c')

deps = [  dependency('libcrypto') ]
src = [ 'crypto.c' ]
lib = shared_library('lorawan', src,
                     dependencies : deps,
                     install : true)
                        
install_headers(['include/lorawan/lorawan.h', 
                 'include/lorawan/crypto.h'], 
                 subdir : 'lorawan')
                 
inc = include_directories('include')

pkg = import('pkgconfig')
pkg.generate(lib,
			 version : '0.1',
             filebase : 'liblorawan')

lorawan_dep = declare_dependency(include_directories : inc, link_with : lib)
