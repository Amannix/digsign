###-(1)变量定义-###

#输出目标库名
EXES= s_hsrsa

#动态库引出函数定义(不需要)
EXPS=

#OBJ扩展名定义
TO=o

#目标库前后缀定义
LIB_PRE=lib
LIB_EXT=.so

#源代码路径
PROJECT_HOME= .
FBASE_HOME = ../src
THIRD_CLASS_HOME = ../ThrClass

#include路径
INCLUDE_DIR	=  -I$(FBASE_HOME) -I$(THIRD_CLASS_HOME)

#dll输出路径
OUTPUT_DIR	= .


#自定义编译(不同平台对同一模块可能有不同编译选项):
DEFS = -DISLIB -DOS_UNIX -D_DEBUG

#清除文件命令
RM = rm -f


###-(2)编译器参数设置-###
CC = gcc
LD = $(CC)

CFLAGS = -c -g -fPIC -O2
LFLAGS = -shared 


#debug版本
ifdef _DEBUG
DEFS= $(DEFS) -D_DEBUG
CFLAGS = -c -g -DNDEBUG -fPIC $(DEFS)
EXES = $(EXES)_d
endif

###-(3)要连接的标准库和自定义库-###
STDLIBS= 
LIBPATH= ../ThrClass/lib
DEFLIBS= -L$(LIBPATH) -lcrypto


#目标文件

OBJS=hs_rsa.$(TO) hs_rsa_tools.$(TO) 


#编译依赖.cpp.o:,
#先清除目标文件

all : cleanobj  $(EXES)

hs_rsa_tools.$(TO): hs_rsa_tools.c
	$(CC) $(CFLAGS) hs_rsa_tools.c $(INCLUDE_DIR)

hs_rsa.$(TO): hs_rsa.c 
	$(CC) $(CFLAGS) hs_rsa.c $(INCLUDE_DIR)

$(EXES): $(OBJS)
	$(LD) $(LFLAGS) -o$(OUTPUT_DIR)/$(LIB_PRE)$(EXES)$(LIB_EXT) $(OBJS) $(STDLIBS) $(DEFLIBS) $(EXPS)

#清理命令

cleanobj:
	$(RM) *.$(TO)
clean:cleanobj
	@echo clean all

