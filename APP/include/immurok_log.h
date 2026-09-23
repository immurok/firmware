/*
 * 日志分级。
 *
 * release-debug 构建（有日志 + 睡眠）2026-09 顶到了 216K 镜像上限，超出的
 * 全是日志：356 条格式串约 12KB 加调用点代码。这里把「只在开发机上有用」
 * 的啰嗦日志收成 PRINT_V，release-debug 编掉，debug 保留。
 *
 * 保留在 PRINT 的：错误 / 拒绝 / 超时 / 状态迁移（睡眠、连接参数、bond、
 * 指纹匹配结果）—— release-debug 存在的意义就是在真机上诊断这些。
 * 降到 PRINT_V 的：每条命令的回显、指纹流水线每一步、OTA 每一步、登记
 * 每次采集这类「顺利路径」进度信息。
 *
 * PRINT_V 关掉时仍走 if(0) 保留参数求值的类型检查，且不会产生 unused
 * 变量告警；优化器把调用和字符串一起删掉。
 */
#ifndef IMMUROK_LOG_H
#define IMMUROK_LOG_H

#ifndef LOG_VERBOSE
#define LOG_VERBOSE 1
#endif

#if LOG_VERBOSE
#define PRINT_V(...)  PRINT(__VA_ARGS__)
#else
#define PRINT_V(...)  do { if(0) PRINT(__VA_ARGS__); } while(0)
#endif

#endif /* IMMUROK_LOG_H */
