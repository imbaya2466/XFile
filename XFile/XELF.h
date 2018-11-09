#pragma once
#include <string>
#include <stdio.h>
#include "elf.h"
#include <exception>  
#include <iostream>
using namespace std;


typedef struct {
	Elf64_Ehdr *header;
} Elf64;
typedef struct {

} Elf32;

//ELF文件结构暂时先写64位的，32位的再加，
//目前共同处理方法预计是自定义俩个结构体专门存储各部分的指针，每个对so的操作都经过本类的方法，
//由本类负责判断32/64之后去选择用那个结构体去解析，存一个指针指向俩个结构体之一即可，在解析时就定好
//所有与ELF相关的操作都应该在这里有函数
class XELF
{
private:
	void *fileCache;

	void doAnalysis();

	Elf64 *elf64=new Elf64;
	Elf32 *elf32=new Elf32;
	enum type_ {e64,e32,eunknow}type;
	


public:
	XELF(FILE *fd);
	XELF( void *cache);
	~XELF();

	void showHeader();



};

