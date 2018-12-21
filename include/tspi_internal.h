enum enum_cube_manage {
	TYPE(TSPI_GENERAL)=0x2110,
	TYPE(TSPI_IN)=0x2111,
	TYPE(TSPI_OUT)=0x2112
};

enum subtype_tspi_in {
	SUBTYPE(TSPI_IN,GETTCMOBJECT)=0x1,
	SUBTYPE(TSPI_IN,GETRANDOM),
	SUBTYPE(TSPI_IN,PCREXTEND),
	SUBTYPE(TSPI_IN,PCRREAD)
};
enum subtype_tspi_out {
	SUBTYPE(TSPI_OUT,GETTCMOBJECT)=0x1,
	SUBTYPE(TSPI_OUT,GETRANDOM),
	SUBTYPE(TSPI_OUT,PCREXTEND),
	SUBTYPE(TSPI_OUT,PCRREAD)
};

typedef struct tspi_in_GetTcmObject{
	int apino;
	int paramSize;
	int hContext;
}__attribute__((packed)) RECORD(TSPI_IN,GETTCMOBJECT);

typedef struct tspi_in_GetRandom{
	int apino;
	int paramSize;
	int hTCM;
	int ulRandomDataLength;
}__attribute__((packed)) RECORD(TSPI_IN,GETRANDOM);

typedef struct tspi_in_PcrExtend{
	int apino;
	int paramSize;
	int hTCM;
	int ulPcrIndex;
	int ulPcrDataLength;
	BYTE * pbPcrData;
}__attribute__((packed)) RECORD(TSPI_IN,PCREXTEND);

typedef struct tspi_in_PcrRead{
	int apino;
	int paramSize;
	int hTCM;
	int ulPcrIndex;
}__attribute__((packed)) RECORD(TSPI_IN,PCRREAD);

typedef struct tspi_out_GetTcmObject{
	int returncode;
	int paramSize;
	int hTCM;
}__attribute__((packed)) RECORD(TSPI_OUT,GETTCMOBJECT);

typedef struct tspi_out_GetRandom{
	int returncode;
	int paramSize;
	int ulRandomDataLength;
	BYTE * rgbRandomData;
}__attribute__((packed)) RECORD(TSPI_OUT,GETRANDOM);

typedef struct tspi_out_PcrExtend{
	int returncode;
	int paramSize;
	int ulPcrValueLength;
	BYTE * rgbPcrValue;
}__attribute__((packed)) RECORD(TSPI_OUT,PCREXTEND);

typedef struct tspi_out_PcrRead{
	int returncode;
	int paramSize;
	int ulPcrValueLength;
	BYTE * rgbPcrValue;
}__attribute__((packed)) RECORD(TSPI_OUT,PCRREAD);

