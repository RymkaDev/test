USE [saggi2022_lin2world]
GO

DROP TABLE [dbo].[user_scheme_buffer]
GO

CREATE TABLE [dbo].[user_scheme_buffer](
	[char_id] [int] NOT NULL,
	[subjob_index] [int] NOT NULL,
	[type] [int] NOT NULL,
	[nombre] [varchar](50) NOT NULL,
	[b0] [int] NOT NULL,
	[b1] [int] NOT NULL,
	[b2] [int] NOT NULL,
	[b3] [int] NOT NULL,
	[b4] [int] NOT NULL,
	[b5] [int] NOT NULL,
	[b6] [int] NOT NULL,
	[b7] [int] NOT NULL,
	[b8] [int] NOT NULL,
	[b9] [int] NOT NULL,
	[b10] [int] NOT NULL,
	[b11] [int] NOT NULL,
	[b12] [int] NOT NULL,
	[b13] [int] NOT NULL,
	[b14] [int] NOT NULL,
	[b15] [int] NOT NULL,
	[b16] [int] NOT NULL,
	[b17] [int] NOT NULL,
	[b18] [int] NOT NULL,
	[b19] [int] NOT NULL,
	[b20] [int] NOT NULL,
	[b21] [int] NOT NULL,
	[b22] [int] NOT NULL,
	[b23] [int] NOT NULL,
	[b24] [int] NOT NULL,
	[b25] [int] NOT NULL,
	[b26] [int] NOT NULL,
	[b27] [int] NOT NULL,
	[b28] [int] NOT NULL,
	[b29] [int] NOT NULL,
	[b30] [int] NOT NULL,
	[b31] [int] NOT NULL,
	[b32] [int] NOT NULL,
	[b33] [int] NOT NULL,
	[b34] [int] NOT NULL,
	[b35] [int] NOT NULL,
	[b36] [int] NOT NULL,
	[b37] [int] NOT NULL,
	[b38] [int] NOT NULL,
	[b39] [int] NOT NULL,
	[b40] [int] NOT NULL,
	[b41] [int] NOT NULL,
	[b42] [int] NOT NULL,
	[b43] [int] NOT NULL,
	[b44] [int] NOT NULL,
	[b45] [int] NOT NULL,
	[b46] [int] NOT NULL,
	[b47] [int] NOT NULL
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [subjob_index]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [type]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [nombre]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b0]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b1]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b2]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b3]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b4]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b5]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b6]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b7]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b8]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b9]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b10]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b11]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b12]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b13]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b14]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b15]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b16]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b17]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b18]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b19]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b20]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b21]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b22]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b23]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b24]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b25]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b26]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b27]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b28]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b29]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b30]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b31]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b32]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b33]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b34]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b35]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b36]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b37]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b38]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b39]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b40]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b41]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b42]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b43]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b44]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b45]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b46]
GO

ALTER TABLE [dbo].[user_scheme_buffer] ADD  DEFAULT ((0)) FOR [b47]
GO

