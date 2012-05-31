/* Copyright (c) 2012 Rebecca (bx) Shapiro

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include <libelfsh.h>
eresi_Addr get_l_relocated(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x314;
}

eresi_Addr get_l_relro_size(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x458;
}

eresi_Addr get_l_prev(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x20;
}
eresi_Addr get_l_next(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x18;
}

//doesn't work., fyi. and not used
eresi_Addr get_l_relainfo(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x20;
}

eresi_Addr get_l_tls_blocksize(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x428;
}

eresi_Addr get_l_buckets(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x308;
}

eresi_Addr get_l_libname_next(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x578;
}

eresi_Addr get_l_direct_opencount(eresi_Addr l)
{
  return ((eresi_Addr) l) + 0x310;
}

eresi_Addr get_l_addr(eresi_Addr l)
{
  return ((eresi_Addr) l);
}
