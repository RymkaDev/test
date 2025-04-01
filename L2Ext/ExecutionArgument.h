#pragma once

typedef INT64 Native;

class CExecutionArgument
{
public:
	static const INT64 DoNothingArgument = 0x009E6598;
	CExecutionArgument(INT64 p) : pointer(p) {};
	INT64 pointer;
	LPVOID _unkn8;
	LPVOID _unkn10;
	LPVOID _unkn18;
};

class CExecutionArgumentMoveToTarget
{
public:
	static const INT64 MoveToTargetArgument = 0x009B17D0;
	CExecutionArgumentMoveToTarget(INT64 p) : pointer(p) {};
//	INT64 pointer;
//	LPVOID _unkn8;
//	BYTE _unkn10;
//	LPVOID _unkn18;
//	LPVOID _unkn24;
//	LPVOID _unkn26;


  INT64 pointer;
  LPVOID _unkn8;
  bool _unkn10;
  bool _unkn12;
  int _unkn14;
  LPVOID _unkn18;



};



