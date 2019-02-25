
#include "XDex.h"

//����ӳ����ļ���ַ
XDex::XDex(void *cache)
{
	fileCache = (u1*)cache;
	doAnalysis();
}

//��ʼ����dex�ļ��������ص�ַ
void XDex::doAnalysis()
{
	header = (DexHeader*)fileCache;
	map_list = (DexMapList*)(fileCache + header->mapOff);
	//�����������
	string_ids_size = header->stringIdsSize;
	string_id_item = (DexStringId*)(fileCache + header->stringIdsOff);
	type_ids_size = header->typeIdsSize;
	type_id_item = (DexTypeId*)(fileCache + header->typeIdsOff);
	proto_ids_size = header->protoIdsSize;
	proto_id_item = (DexProtoId*)(fileCache + header->protoIdsOff);
	field_ids_size = header->fieldIdsSize;
	field_id_item = (DexFieldId*)(fileCache + header->fieldIdsOff);
	method_ids_size = header->methodIdsSize;
	method_id_item = (DexMethodId*)(fileCache + header->methodIdsOff);

	class_defs_size = header->classDefsSize;
	class_def_item = (DexClassDef*)(fileCache + header->classDefsOff);

	//����ִ���
	for (int i=0;i<string_ids_size;i++)
	{
		void *string_data_item = string_id_item[i].stringDataOff + fileCache;
		u4 stringlength = readUnsignedLeb128((u1**)&string_data_item);
		if (stringlength==0)
		{
			stringarry.push_back("");
		}
		else
		{
			const char* stringval = (char*)string_data_item;
			stringarry.push_back(stringval);
		}


	}




}

