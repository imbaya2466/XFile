
#include "XDex.h"
#include <stdio.h>
#include <sstream>
//传入映射的文件地址
XDex::XDex(void *cache)
{
	fileCache = (u1*)cache;
	doAnalysis();
}

//开始解析dex文件，填充相关地址
void XDex::doAnalysis()
{
	header = (DexHeader*)fileCache;
	map_list = (DexMapList*)(fileCache + header->mapOff);
	//构建索引相关
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

	//填充字串池
	for (u4 i=0;i<string_ids_size;i++)
	{
		void *string_data_item = string_id_item[i].stringDataOff + fileCache;
		u4 stringlength = readUnsignedLeb128((u1**)&string_data_item);
		if (stringlength==0)
		{
			stringarray.push_back("");
		}
		else
		{
			const char* stringval = (char*)string_data_item;
			stringarray.push_back(stringval);
		}


	}

	//填充类型池
	for (u4 i=0;i< type_ids_size;i++)
	{
		typearray.push_back(type_id_item[i].descriptorIdx);
	}






}

void XDex::showAllClass()
{
	for (u4 i=0;i< class_defs_size;i++)
	{
		DexClassDef class_def = class_def_item[i];
		string classname = stringarray[typearray[class_def.classIdx]];

		u4 access_flags = class_def.accessFlags;
		string supername;
		if (class_def.superclassIdx!= kDexNoIndex)
		{
			supername = stringarray[typearray[class_def.superclassIdx]];
		}
		
		DexTypeList *interfaces = (DexTypeList *)(fileCache + class_def.interfacesOff);

		string filename;
		if (class_def.sourceFileIdx != kDexNoIndex)
		{
			filename = stringarray[class_def.sourceFileIdx];
		}
	

		//这三个属性可能为0
		DexAnnotationsDirectoryItem *annotations= (DexAnnotationsDirectoryItem *)(fileCache + class_def.annotationsOff);
		u1* pclass_data = fileCache + class_def.classDataOff;
		DexEncodedArray* static_values= (DexEncodedArray *)(fileCache + class_def.staticValuesOff);

		u4 static_fields_size = 0;
		u4 instance_fields_size = 0;
		u4 direct_methods_size = 0;
		u4 virtual_methods_size = 0;

		if (class_def.classDataOff!=0)
		{
			static_fields_size = readUnsignedLeb128(&pclass_data);
			instance_fields_size = readUnsignedLeb128(&pclass_data);
			direct_methods_size = readUnsignedLeb128(&pclass_data);
			virtual_methods_size = readUnsignedLeb128(&pclass_data);
		}



		//输出类信息


		printf("%d-%s(", i,classname.c_str());
		vector<string> flags = analysisAccessFlags(access_flags);
	
		for (auto &ls:flags)
		{
			printf("%s,", ls.c_str());
		}
		printf(")");

		if (class_def.superclassIdx != kDexNoIndex)
		{
			printf(" extends:%s ", supername.c_str());
		}

		if (class_def.interfacesOff!=0)
		{
			printf(" interface:");
			vector<u2> interfaces_id = readTypeList(interfaces);
			for (auto &ls:interfaces_id)
			{
				printf("%s,",stringarray[typearray[ls]].c_str());
			}
		}


		if (class_def.sourceFileIdx != kDexNoIndex)
		{
			printf(" filename:%s ", filename.c_str());
		}

		printf(" class_data:%d %d %d %d", static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size);

		printf("\n");
	}
}



void XDex::showClassData(u4 index)
{

	if (index>=class_defs_size)
	{
		return;

	}


	DexClassDef class_def = class_def_item[index];


	//如果此类没有类数据，则该值为 0。如此类是标记接口
	if (class_def.classDataOff==0)
	{
		printf("class:%s  no data\n", stringarray[typearray[class_def.classIdx]].c_str());
		return;
	}

	u1* pclass_data = fileCache + class_def.classDataOff;

	u4 static_fields_size = readUnsignedLeb128(&pclass_data);
	u4 instance_fields_size = readUnsignedLeb128(&pclass_data);
	u4 direct_methods_size = readUnsignedLeb128(&pclass_data);
	u4 virtual_methods_size = readUnsignedLeb128(&pclass_data);

	printf("class:%s\n", stringarray[typearray[class_def.classIdx]].c_str());


	printf("static field:\n");
	u4 field_idx_diff = 0;
	for (u4 i=0;i<static_fields_size;i++)
	{
		
		field_idx_diff+= readUnsignedLeb128(&pclass_data);
		u4 access_flags= readUnsignedLeb128(&pclass_data);
		u4 type_idx = field_id_item[field_idx_diff].typeIdx;
		u4 name_idx = field_id_item[field_idx_diff].nameIdx;

		vector<string> flags = analysisAccessFlags(access_flags);
		printf("\t");
		for (auto &ls : flags)
		{
			printf("%s ", ls.c_str());
		}
		printf("%s %s;\n",stringarray[typearray[type_idx]].c_str(),stringarray[name_idx].c_str());

	}

	printf("instance field:\n");
	field_idx_diff = 0;
	for (u4 i = 0; i < instance_fields_size; i++)
	{
		field_idx_diff += readUnsignedLeb128(&pclass_data);
		u4 access_flags = readUnsignedLeb128(&pclass_data);
		u4 type_idx = field_id_item[field_idx_diff].typeIdx;
		u4 name_idx = field_id_item[field_idx_diff].nameIdx;

		vector<string> flags = analysisAccessFlags(access_flags);
		printf("\t");
		for (auto &ls : flags)
		{
			printf("%s ", ls.c_str());
		}
		printf("%s %s;\n", stringarray[typearray[type_idx]].c_str(), stringarray[name_idx].c_str());

	}

	printf("direct methods:\n");
	u4 method_idx_diff = 0;
	for (u4 i = 0; i < direct_methods_size; i++)
	{
		method_idx_diff += readUnsignedLeb128(&pclass_data);
		u4 access_flags = readUnsignedLeb128(&pclass_data);
		u4 code_off = readUnsignedLeb128(&pclass_data);
		


		vector<string> flags = analysisAccessFlags(access_flags);
		printf("\t");
		for (auto &ls : flags)
		{
			printf("%s ", ls.c_str());
		}
		printf("%s\n", analysisMethod_id(method_idx_diff).c_str());

		//解析输出code内容
		if (code_off!=0)
		{
			DexCode* dexcode = (DexCode*)(fileCache+code_off);
			printf("\t  ");
			printf("registers_size:%d ins_size:%d outs_size	:%d \n",dexcode->registersSize,dexcode->insSize,dexcode->outsSize);

		}

	}


	printf("virtual methods:\n");
	method_idx_diff = 0;
	for (u4 i = 0; i < virtual_methods_size; i++)
	{
		method_idx_diff += readUnsignedLeb128(&pclass_data);
		u4 access_flags = readUnsignedLeb128(&pclass_data);
		u4 code_off = readUnsignedLeb128(&pclass_data);



		vector<string> flags = analysisAccessFlags(access_flags);
		printf("\t");
		for (auto &ls : flags)
		{
			printf("%s ", ls.c_str());
		}
		printf("%s\n", analysisMethod_id(method_idx_diff).c_str());

		//解析输出code内容
		if (code_off != 0)
		{
			DexCode* dexcode = (DexCode*)(fileCache + code_off);
			printf("\t  ");
			printf("registers_size:%d ins_size:%d outs_size	:%d \n", dexcode->registersSize, dexcode->insSize, dexcode->outsSize);

		}

	}
}




string XDex::analysisMethod_id(u4 id)
{

	if (id >= method_ids_size)
	{
		return string();
	}

	u2 class_idx = method_id_item[id].classIdx;
	u2 proto_idx = method_id_item[id].protoIdx;
	u4 name_idx = method_id_item[id].nameIdx;


	u4 return_type_idx = proto_id_item[proto_idx].returnTypeIdx;
	DexTypeList *parameters_off = (DexTypeList *)(fileCache + proto_id_item[proto_idx].parametersOff);
	vector<u2> parameters;
	if (proto_id_item[proto_idx].parametersOff!=0)
	{
		parameters = readTypeList(parameters_off);
	}

	ostringstream ret_string_stream;

	ret_string_stream << stringarray[typearray[return_type_idx]]<<" ";
	ret_string_stream << stringarray[name_idx] << " ";
	ret_string_stream << "(";
	for (auto &ls:parameters)
	{
		ret_string_stream << stringarray[typearray[ls]] << ",";
	}
	ret_string_stream << ")";


	return ret_string_stream.str();

}