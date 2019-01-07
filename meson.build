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


cython = find_program('cython3', required : false)
py3_dep = dependency('python3', required : false)
if cython.found() and py3_dep.found()
  pyx_c = custom_target('lorawan_pyx',
  output : 'lorawan_pyx.c',
  input : 'lorawan.pyx',
  command : [cython, '@INPUT@', '-o', '@OUTPUT@'])
  
  py3_mod = import('python3')
  py3 = py3_mod.find_python()
  
  slib = py3_mod.extension_module('pylorawan', 'crypto.c', pyx_c, dependencies : py3_dep)
endif