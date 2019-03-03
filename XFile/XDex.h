#pragma once

//这次尽力使用良好的c++架构与语法
#include "DexFile.h"
#include <vector>
#include <string>
using namespace std;

class XDex
{
public:

	XDex(void *cache);

	//展示全部class
	void showAllClass();
	//显示某class详细data信息
	void showClassData(u4 index);
	//根据method_id_item的id解析出方法的java代码表示
	string analysisMethod_id(u4 id);






	//从流中读取Leb128
	static u4 readUnsignedLeb128( u1** pStream)
	{
		u1* ptr = *pStream;
		u4 result = *(ptr++);

		if (result > 0x7f) {
			u4 cur = *(ptr++);
			result = (result & 0x7f) | ((cur & 0x7f) << 7);
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 14;
				if (cur > 0x7f) {
					cur = *(ptr++);
					result |= (cur & 0x7f) << 21;
					if (cur > 0x7f) {
						/*
						 * Note: We don't check to see if cur is out of
						 * range here, meaning we tolerate garbage in the
						 * high four-order bits.
						 */
						cur = *(ptr++);
						result |= cur << 28;
					}
				}
			}
		}
		*pStream = ptr;
		return result;
	}

	//解析flag
	static vector<string> analysisAccessFlags(u4 flag)
	{
		vector<string> ret;
		for (int i=0;i<18;i++)
		{
			u4 Mask = 1 << i;
			if (Mask & flag)
			{
				switch (i)
				{
				case 0:
					ret.push_back("PUBLIC");
					break;
				case 1:
					ret.push_back("PRIVATE");
					break;
				case 2:
					ret.push_back("PROTECTED");
					break;
				case 3:
					ret.push_back("STATIC");
					break;
				case 4:
					ret.push_back("FINAL");
					break;
				case 5:
					ret.push_back("SYNCHRONIZED");
					break;
				case 6:
					ret.push_back("VOLATILE");
					break;
				case 7:
					ret.push_back("TRANSIENT");
					break;
				case 8:
					ret.push_back("NATIVE");
					break;
				case 9:
					ret.push_back("INTERFACE");
					break;
				case 10:
					ret.push_back("ABSTRACT");
					break;
				case 11:
					ret.push_back("STRICT");
					break;
				case 12:
					ret.push_back("SYNTHETIC");
					break;
				case 13:
					ret.push_back("ANNOTATION");
					break;
				case 14:
					ret.push_back("ENUM");
					break;
				case 15:
					break;
				case 16:
					ret.push_back("CONSTRUCTOR");
					break;
				case 17:
					ret.push_back("SYNCHRONIZED");
					break;



				default:
					break;
				}
			}
		}
		return ret;

	}

	//从内存中解析出TypeList
	static vector<u2> readTypeList(DexTypeList* list)
	{
		vector<u2> ret;
		for (u4 i=0;i<list->size;i++)
		{
			ret.push_back(list->list[i].typeIdx);
		}
		return ret;
	}




private:
	u1 *fileCache;

	DexHeader *header;
	DexMapList *map_list;

	u4 string_ids_size;
	DexStringId *string_id_item;
	u4 type_ids_size;
	DexTypeId *type_id_item;
	u4 proto_ids_size;
	DexProtoId *proto_id_item;
	u4 field_ids_size;
	DexFieldId *field_id_item;
	u4 method_ids_size;
	DexMethodId *method_id_item;

	u4 class_defs_size;
	DexClassDef *class_def_item;

	//字串池
	vector<string> stringarray;
	//类型池
	vector<u4> typearray;
	

	void doAnalysis();

	

	


};

