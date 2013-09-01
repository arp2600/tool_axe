// Copyright (c) 2011-2012, Richard Osborne, All rights reserved
// This software is freely distributable under a derivative of the
// University of Illinois/NCSA Open Source License posted in
// LICENSE.txt and at <http://github.xcore.com/>

#ifndef _PortInterface_h_
#define _PortInterface_h_

#include "Config.h"

namespace axe {

struct Signal;

class PortInterface {
protected:
  ~PortInterface();
public:
  virtual void seePinsChange(const Signal &value, ticks_t time) = 0;
};

/// Port interface which delgates seePinsChange calls to a member function of
/// another class.
template <class T>
class PortInterfaceMemberFuncDelegate : public PortInterface {
  T &obj;
  void (T::*func)(const Signal &value, ticks_t time);
public:
  PortInterfaceMemberFuncDelegate(T &o, void (T::*f)(const Signal &value, ticks_t time)) :
  obj(o),
  func(f) {}
  void seePinsChange(const Signal &value, ticks_t time) override {
    (obj.*func)(value, time);
  }
};
  
} // End axe namespace

#endif // _PortInterface_h_
