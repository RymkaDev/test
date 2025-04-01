#include "StdAfx.h"

void CCreatureController::AsyncDoNothing()
{
	CExecutionArgument arg(CExecutionArgument::DoNothingArgument);
	asynchronousExecution.AddExecutable(this, CAsynchronousExecution::DoNothing, &arg);
}

void CCreatureController::AsyncMoveToTarget(CCreature* pCreature, BYTE nControl)
{
	CExecutionArgumentMoveToTarget arg(CExecutionArgumentMoveToTarget::MoveToTargetArgument);

	arg._unkn8 = pCreature;
	arg._unkn10 = nControl;
	arg._unkn12 = 0;
	arg._unkn14 = 0;
	arg._unkn18 = 0;

	asynchronousExecution.AddExecutable2(this, CAsynchronousExecution::MoveToTarget, &arg);
}

