USE [saggi2022_lin2world]

GO
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Donaciones_Pendientes]') AND type in (N'U'))
BEGIN
CREATE TABLE [dbo].[Donaciones_Pendientes](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[fecha] [datetime] NULL,
	[personaje_id] [varchar](50) NULL,
	[personaje] [varchar](50) NULL,
	[coins] [varchar](50) NULL,
	[pesos] [int] NULL,
	[estado] [int] NULL,
 CONSTRAINT [PK_Donaciones_Pendientes] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
END


GO
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[Donaciones_Entregadas]') AND type in (N'U'))
BEGIN
CREATE TABLE [dbo].[Donaciones_Entregadas](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[fecha] [datetime] NULL,
	[personaje_id] [varchar](50) NULL,
	[personaje] [varchar](50) NULL,
	[cantidad] [varchar](50) NULL,
	[informacion] [varchar](50) NULL,
	[codigo] [varchar](50) NULL CONSTRAINT [DF_Donaciones_Entregadas_codigo]  DEFAULT ((0)),
	[pesos] [int] NULL,
 CONSTRAINT [PK_Donaciones_Entregadas] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (IGNORE_DUP_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
END


USE [saggi2022_lin2world]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[Donaciones_Regaladas](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[fecha] [datetime] NULL,
	[personaje_id] [varchar](50) NULL,
	[personaje] [varchar](50) NULL,
	[coins] [varchar](50) NULL,
	[pesos] [int] NULL,
	[estado] [int] NULL,
 CONSTRAINT [PK_Donaciones_Regaladas] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO




USE [saggi2022_lin2world]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO

CREATE TABLE [dbo].[web_votereward](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[proximo_voto] [varchar](255) NOT NULL,
	[ip] [varchar](255) NULL,
	[cuenta] [varchar](255) NULL,
	[personaje] [varchar](255) NULL,
	[personaje_name] [varchar](255) NULL,
	[fecha_ultimo_voto] [varchar](255) NULL,
	[hwid] [varchar](50) NULL,
 CONSTRAINT [PK__web_votereward__286DEFE4] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO





SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING OFF
GO
CREATE TABLE [dbo].[Registros_Actividad](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[func] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[respuesta] [varchar](200) COLLATE Modern_Spanish_CI_AS NULL,
	[var1] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[var2] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[var3] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[var4] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[var5] [varchar](50) COLLATE Modern_Spanish_CI_AS NULL,
	[fecha] [datetime] NULL
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF


















