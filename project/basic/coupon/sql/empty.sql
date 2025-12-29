DROP TABLE IF EXISTS `template_coupon`;
CREATE TABLE `template_coupon` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `coupon_no` varchar(44) NOT NULL COMMENT '券码',
      `activity_id` varchar(32) NOT NULL COMMENT '券所属的活动id',
      `activity_cycle` varchar(32) NOT NULL COMMENT '券所属的活动id的周期',
      `type` int unsigned NOT NULL COMMENT '券类型: 0初始(无效值);1无门槛折扣;2满减;3无门槛打折;4带上限打折;5余额型',
      `status` int unsigned NOT NULL COMMENT '券状态 ',
      `attr` json NOT NULL COMMENT '券属性，各种参数',
      `user_id` bigint unsigned NOT NULL COMMENT '券所属的user_id',
      `created` datetime NOT NULL COMMENT '创建时间',
      `updated` datetime NOT NULL COMMENT '最后更新时间',
      `started` datetime NOT NULL DEFAULT '1970-01-01 00:00:00' COMMENT '启用时间',
      `expired` datetime NOT NULL DEFAULT '1970-01-01 00:00:00' COMMENT '过期时间',
      `redemption` datetime NOT NULL DEFAULT '1970-01-01 00:00:00' COMMENT '核销时间',
      `cancel` datetime NOT NULL DEFAULT '1970-01-01 00:00:00' COMMENT '作废时间',
      `context` text NOT NULL COMMENT '备注',
      `extension` json NOT NULL COMMENT '扩展字段',
      `signature` varchar(44) NOT NULL COMMENT '数据签名',
      PRIMARY KEY (`id`),
      UNIQUE KEY `coupon_no_UNIQUE` (`coupon_no`),
      KEY `type_INDEX` (`type`),
      KEY `status_INDEX` (`status`),
      KEY `created_INDEX` (`created`),
      KEY `started_INDEX` (`started`),
      KEY `expired_INDEX` (`expired`),
      KEY `redemption_INDEX` (`redemption`),
      KEY `updated_INDEX` (`updated`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT = '券表';

DROP TABLE IF EXISTS `template_record`;
CREATE TABLE `template_record` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `coupon_no` varchar(44) NOT NULL COMMENT '券码',
      `type` int unsigned NOT NULL COMMENT '操作类型',
      `old_status` int unsigned NOT NULL COMMENT '源券状态 ',
      `new_status` int unsigned NOT NULL COMMENT '新券状态 ',
      `attr` json NOT NULL COMMENT '操作属性',
      `operator_id` bigint unsigned NOT NULL COMMENT '操作员id,如核销商户id',
      `created` datetime NOT NULL COMMENT '创建时间',
      `context` text NOT NULL COMMENT '备注',
      `extension` json,
      `signature` varchar(44) NOT NULL,
      PRIMARY KEY (`id`),
      KEY `coupon_no_INDEX` (`coupon_no`),
      KEY `type_INDEX` (`type`),
      KEY `created_INDEX` (`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT = '操作流水表';
