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


	vector<string> stringarry;


	void doAnalysis();

	



};

