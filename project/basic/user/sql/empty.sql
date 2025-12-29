DROP TABLE IF EXISTS `template_user`;
CREATE TABLE `template_user` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `user_id` bigint unsigned NOT NULL COMMENT '用户唯一标识',
      `salt` varchar(16) NOT NULL COMMENT '盐值，随机生成，和数据加密有关',
      `src_id` int unsigned NOT NULL COMMENT '来源id',
      `status` int unsigned NOT NULL COMMENT '用户状态，0正常 1冻结 2销户 3异常数据',
      `type` int unsigned NOT NULL COMMENT '用户类型 0普通用户',
      `param` json NOT NULL COMMENT '用户属性相关的非敏感参数',
      `attr` json NOT NULL COMMENT '用户个人数据，证件号，电话等敏感数据',
      `created` datetime NOT NULL COMMENT '创建时间',
      `updated` datetime NOT NULL COMMENT '最后更新时间',
      `context` text NOT NULL COMMENT '备注',
      `extension` json NOT NULL COMMENT '扩展字段',
      `signature` varchar(44) NOT NULL COMMENT '数据签名',
      PRIMARY KEY (`id`),
      UNIQUE KEY `user_id_UNIQUE` (`user_id`),
      KEY `type_INDEX` (`type`),
      KEY `created_INDEX` (`created`),
      KEY `updated_INDEX` (`updated`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT = '券表';

DROP TABLE IF EXISTS `template_record`;
CREATE TABLE `template_record` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `user_id` bigint unsigned NOT NULL COMMENT '操作的uid',
      `type` int unsigned NOT NULL COMMENT '操作类型 0创建 1更新 2冻结 3解冻 4销户 5异常',
      `attr` json NOT NULL COMMENT '操作属性',
      `operator_id` bigint unsigned NOT NULL COMMENT '操作员id',
      `created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
      `context` text NOT NULL COMMENT '备注',
      `extension` json,
      `signature` varchar(44) NOT NULL,
      PRIMARY KEY (`id`),
      KEY `user_id_INDEX` (`user_id`),
      KEY `type_INDEX` (`type`),
      KEY `created_INDEX` (`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT = '操作流水表';
