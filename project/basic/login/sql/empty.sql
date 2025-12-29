DROP TABLE IF EXISTS `template_login`;
CREATE TABLE `template_login` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `appid` varchar(32) NOT NULL COMMENT '标记登录的app平台',
      `salt` varchar(16) NOT NULL COMMENT '盐值，随机生成，和数据加密有关',
      `type` int unsigned NOT NULL COMMENT '登入类型 0普通(验证key) 1已授权(已通过三方登陆鉴权) ...',
      `auth_key` varchar(64) NOT NULL COMMENT '登陆验证的key值',
      `status` int unsigned NOT NULL COMMENT '账户状态，0正常 1冻结 2销户 3异常数据',
      `attr` json NOT NULL COMMENT '其它一些登陆属性',
      `param` json NOT NULL COMMENT '其它一些参数属性',
      `user_id` bigint unsigned NOT NULL COMMENT '登陆后绑定的用户唯一标识',
      `created` datetime NOT NULL COMMENT '创建时间',
      `updated` datetime NOT NULL COMMENT '最后更新时间',
      `context` text NOT NULL COMMENT '备注',
      `extension` json NOT NULL COMMENT '扩展字段',
      `signature` varchar(44) NOT NULL COMMENT '数据签名',
      PRIMARY KEY (`id`),
      UNIQUE KEY `login_in_UNIQUE` (`auth_key`, `appid`),
      KEY `user_id_INDEX` (`user_id`),
      KEY `type_INDEX` (`type`),
      KEY `created_INDEX` (`created`),
      KEY `updated_INDEX` (`updated`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT = '登录表';
