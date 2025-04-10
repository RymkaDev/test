USE [saggi2022_lin2world]
GO

/****** Object:  Table [dbo].[achivments_hwids]    Script Date: 07/06/2022 16:42:45 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[achivments_hwids](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[achiv_id] [int] NOT NULL,
	[hwid] [nvarchar](50) NOT NULL,
	[time] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[achivments_hwids] ADD  CONSTRAINT [DF_achivments_hwids_achiv_id]  DEFAULT ((0)) FOR [achiv_id]
GO

ALTER TABLE [dbo].[achivments_hwids] ADD  CONSTRAINT [DF_achivments_hwids_hwid]  DEFAULT ((0.)) FOR [hwid]
GO

ALTER TABLE [dbo].[achivments_hwids] ADD  CONSTRAINT [DF_achivments_hwids_time]  DEFAULT ((0)) FOR [time]
GO



USE [saggi2022_lin2world]
GO

/****** Object:  Table [dbo].[achivments_user_mobs]    Script Date: 07/06/2022 16:43:22 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[achivments_user_mobs](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[char_id] [int] NOT NULL,
	[npc_id] [int] NOT NULL,
	[count] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[achivments_user_mobs] ADD  CONSTRAINT [DF_achivments_user_mobs_char_id]  DEFAULT ((0)) FOR [char_id]
GO

ALTER TABLE [dbo].[achivments_user_mobs] ADD  CONSTRAINT [DF_achivments_user_mobs_count]  DEFAULT ((0)) FOR [count]
GO



USE [saggi2022_lin2world]
GO

/****** Object:  Table [dbo].[achivments_user_states]    Script Date: 07/06/2022 16:43:44 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[achivments_user_states](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[char_id] [int] NOT NULL,
	[achiv_id] [int] NOT NULL,
	[state] [int] NOT NULL,
	[time] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[achivments_user_states] ADD  CONSTRAINT [DF_achivments_user_states_char_id]  DEFAULT ((0)) FOR [char_id]
GO

ALTER TABLE [dbo].[achivments_user_states] ADD  CONSTRAINT [DF_achivments_user_states_achiv_id]  DEFAULT ((0)) FOR [achiv_id]
GO

ALTER TABLE [dbo].[achivments_user_states] ADD  CONSTRAINT [DF_achivments_user_states_state]  DEFAULT ((0)) FOR [state]
GO

ALTER TABLE [dbo].[achivments_user_states] ADD  CONSTRAINT [DF_achivments_user_states_time]  DEFAULT ((0)) FOR [time]
GO






USE [saggi2022_lin2world]
GO

/****** Object:  Table [dbo].[achivments_user_vars]    Script Date: 07/06/2022 16:44:01 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[achivments_user_vars](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[char_id] [int] NOT NULL,
	[olympiad] [int] NOT NULL,
	[deathmatch] [int] NOT NULL,
	[lastteamstanding] [int] NOT NULL,
	[destroythebase] [int] NOT NULL,
	[capturetheflag] [int] NOT NULL,
	[savescapturetheflag] [int] NOT NULL,
	[pvp] [int] NOT NULL,
	[pk] [int] NOT NULL,
	[hero] [int] NOT NULL,
	[login] [int] NOT NULL,
	[vote] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_char_id]  DEFAULT ((0)) FOR [char_id]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_olympiad]  DEFAULT ((0)) FOR [olympiad]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_deathmatch]  DEFAULT ((0)) FOR [deathmatch]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_lastteamstanding]  DEFAULT ((0)) FOR [lastteamstanding]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_destroythebase]  DEFAULT ((0)) FOR [destroythebase]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_capturetheflag]  DEFAULT ((0)) FOR [capturetheflag]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_savescapturetheflag]  DEFAULT ((0)) FOR [savescapturetheflag]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_pvp]  DEFAULT ((0)) FOR [pvp]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_pk]  DEFAULT ((0)) FOR [pk]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_hero]  DEFAULT ((0)) FOR [hero]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_login]  DEFAULT ((0)) FOR [login]
GO

ALTER TABLE [dbo].[achivments_user_vars] ADD  CONSTRAINT [DF_achivments_user_vars_vote]  DEFAULT ((0)) FOR [vote]
GO




USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsSetVars]    Script Date: 07/06/2022 0:42:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsSetVars]
(
	@var_char_id as INT,
	@var_Olympiad as INT,
	@var_DeathMatch as INT,
	@var_LastTeamStanding as INT,
	@var_DestroyTheBase as INT,
	@var_CaptureTheFlag as INT,
	@var_SavesCaptureTheFlag as INT,
	@var_PvP as INT,
	@var_Pk as INT,
	@var_Hero as INT,
	@var_Login as INT,
	@var_Vote as INT
)
AS

SET NOCOUNT ON;

IF EXISTS(SELECT * FROM [achivments_user_vars] WHERE [char_id] = @var_char_id)
BEGIN
	UPDATE [achivments_user_vars] SET [olympiad] = @var_olympiad, [deathmatch] = @var_deathmatch, [lastteamstanding] = @var_lastteamstanding, [destroythebase] = @var_destroythebase, [capturetheflag] = @var_capturetheflag, [savescapturetheflag] = @var_savescapturetheflag, [pvp] = @var_pvp, [pk] = @var_pk, [hero] = @var_hero, [login] = @var_login, [vote] = @var_vote WHERE [char_id] = @var_char_id
END
ELSE
BEGIN
	INSERT INTO [achivments_user_vars] ([char_id], [Olympiad], [DeathMatch], [LastTeamStanding], [DestroyTheBase], [CaptureTheFlag], [SavesCaptureTheFlag], [PvP], [Pk], [Hero], [Login], [Vote]) VALUES (@var_char_id, @var_Olympiad, @var_DeathMatch, @var_LastTeamStanding, @var_DestroyTheBase, @var_CaptureTheFlag, @var_SavesCaptureTheFlag, @var_PvP, @var_Pk, @var_Hero, @var_Login, @var_Vote)
END
GO





USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsGetVars]    Script Date: 08/06/2022 3:08:59 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsGetVars]
(
	@char_id as INT
)
AS

SET NOCOUNT ON;
SELECT [Olympiad], [DeathMatch], [LastTeamStanding], [DestroyTheBase], [CaptureTheFlag], [SavesCaptureTheFlag], [PvP], [Pk], [Hero], [Login], [vote] FROM [achivments_user_vars] WHERE [char_id] = @char_id

GO





USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsSetStates]    Script Date: 07/06/2022 2:06:22 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsSetStates]
(
	@var_char_id as INT,
	@var_achivId as INT,
	@var_state as INT,
	@var_time as INT

)
AS

SET NOCOUNT ON;

IF EXISTS(SELECT * FROM [achivments_user_states] WHERE [char_id] = @var_char_id AND [achiv_id] = @var_achivId)
BEGIN
	UPDATE [achivments_user_states] SET [state] = @var_state, [time] = @var_time WHERE [char_id] = @var_char_id AND [achiv_id] = @var_achivId
END
ELSE
BEGIN
	INSERT INTO [achivments_user_states] ([char_id], [achiv_id], [state],  [time]) VALUES (@var_char_id, @var_achivId, @var_state, @var_time)
END

GO






USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsSetMobs]    Script Date: 07/06/2022 2:06:22 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsSetMobs]
(
	@var_char_id as INT,
	@var_npc_id as INT,
	@var_count as INT

)
AS

SET NOCOUNT ON;

IF EXISTS(SELECT * FROM [achivments_user_mobs] WHERE [char_id] = @var_char_id AND [npc_id] = @var_npc_id)
BEGIN
	UPDATE [achivments_user_mobs] SET [count] = @var_count WHERE [char_id] = @var_char_id AND [npc_id] = @var_npc_id
END
ELSE
BEGIN
	INSERT INTO [achivments_user_mobs] ([char_id], [npc_id], [count]) VALUES (@var_char_id, @var_npc_id, @var_count)
END

GO





USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsGetMobs]    Script Date: 07/06/2022 2:29:32 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsGetMobs]
(
	@char_id as INT
)
AS

SET NOCOUNT ON;
SELECT [npc_id], [count] FROM [achivments_user_mobs] WHERE [char_id] = @char_id

GO




USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsGetStates]    Script Date: 07/06/2022 2:29:32 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsGetStates]
(
	@char_id as INT
)
AS

SET NOCOUNT ON;
SELECT [achiv_id], [state], [time] FROM [achivments_user_states] WHERE [char_id] = @char_id

GO




USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsGetHwids]    Script Date: 07/06/2022 7:20:00 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsGetHwids]
AS

SET NOCOUNT ON;
SELECT [achiv_id], [hwid], [time] FROM [achivments_hwids]

GO




USE [saggi2022_lin2world]
GO
/****** Object:  StoredProcedure [dbo].[lin_AchivmentsSetHwids]    Script Date: 07/06/2022 7:19:21 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[lin_AchivmentsSetHwids]
(
	@var_achivId as INT,
	@var_hwid as NVARCHAR(50),
	@var_time as INT

)
AS

SET NOCOUNT ON;

IF EXISTS(SELECT * FROM [achivments_hwids] WHERE [achiv_id] = @var_achivId AND [hwid] = @var_hwid)
BEGIN
	UPDATE [achivments_hwids] SET [time] = @var_time  WHERE [achiv_id] = @var_achivId AND [hwid] = @var_hwid
END
ELSE
BEGIN
	INSERT INTO [achivments_hwids] ([achiv_id], [hwid], [time]) VALUES (@var_achivId, @var_hwid, @var_time)
END

GO