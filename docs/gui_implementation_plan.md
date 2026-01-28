# GUI 实现方案与实施计划（基准版）

## 1. 目标与范围
### 1.1 目标
- 提供独立 GUI，用于读取并展示 `version-inject` 对游戏的修改状态。
- 支持“参数配置”“热键绑定”两类可编辑项，并写入 `game_helper.ini`。
- GUI 写入后 **重启生效**（不做热重载）。

### 1.2 范围内
- 读取/写入 `game_helper.ini`
- 读取共享内存状态
- 三页结构：首页 / 参数配置 / 热键绑定

### 1.3 范围外
- 日志查看页
- 高度定制 UI 主题与动画

---

## 2. 技术选型与目录规划
### 2.1 技术栈
- GUI：C# WPF（.NET）
- 状态通道：共享内存（MemoryMappedFile）
- 参数元数据：JSON

### 2.2 放置路径
- GUI 工程：`/tools/gui/GameHelperGUI`
- 配置元数据：`/tools/gui/GameHelperGUI/config/params.json`
- 运行时配置文件：`game_helper.ini`（与 GUI/HelperStart 同目录）

---

## 3. 运行时架构与数据通路
### 3.1 逻辑关系
```
Game (version-inject DLL)
   └─ 写共享内存：Global\\GameHelperStatus

GUI (GameHelperGUI.exe)
   ├─ 读取共享内存 -> 首页展示
   └─ 读写 game_helper.ini -> 参数/热键配置
```

### 3.2 状态更新频率
- DLL 写共享内存：200~500ms
- GUI 读取：500~1000ms
- 超时阈值：> 3000ms 显示“未连接”

### 3.3 版本兼容策略
- 共享内存结构包含 `version` + `size`
- GUI 校验不匹配时提示“版本不兼容”

---

## 4. 共享内存结构设计（V1）
```
struct HelperStatusV1 {
  uint32_t version;
  uint32_t size;
  uint64_t last_tick_ms;
  uint32_t pid;
  bool process_alive;

  bool auto_transparent_enabled;
  bool fullscreen_attack_target;
  bool fullscreen_attack_patch_on;
  int  attract_mode;
  bool attract_positive;
  bool summon_enabled;
  uint64_t summon_last_tick;

  bool fullscreen_skill_enabled;
  bool fullscreen_skill_active;
  uint32_t fullscreen_skill_hotkey;
};
```

共享内存命名：
- `Global\\GameHelperStatus`

---

## 5. 配置元数据 JSON（params.json）
### 5.1 目标
- UI 自动生成参数表单
- 类型/默认值/范围/说明集中维护

### 5.2 结构示例
```
{
  "sections": [
    {
      "name": "startup",
      "title": "启动参数",
      "items": [
        {"key":"startup_delay_ms","label":"启动延迟(ms)","type":"int","default":0,"min":0,"max":60000},
        {"key":"safe_mode","label":"安全模式","type":"bool","default":false}
      ]
    }
  ]
}
```

---

## 6. 热键绑定设计
### 6.1 绑定策略
- 单键绑定（不做组合键）
- 捕获 `KeyDown` -> 转 VirtualKey -> 写入 INI
- ESC 取消，Backspace 清除（写 0）
- 冲突提示但允许保存

### 6.2 INI 结构（示例）
```
[hotkey]
toggle_transparent=0x71
toggle_fullscreen_attack=0x72
summon_doll=0x7B
attract_mode1=0x37
attract_mode2=0x38
attract_mode3=0x39
attract_mode4=0x30
toggle_attract_direction=0xBD
toggle_fullscreen_skill=0x24
```

---

## 7. 页面布局草图（简约版）
### 7.1 首页
- 连接状态 / PID / 最后更新时间
- 功能状态卡片
  - 全屏攻击（目标/当前）
  - 自动透明
  - 吸怪模式 + 方向
  - 召唤人偶
  - 全屏技能（启用/激活/热键）

### 7.2 参数配置
- 左侧分组列表（按 section）
- 右侧表单（由 JSON 自动生成）
- 操作按钮：保存 / 重载 / 恢复默认

### 7.3 热键绑定
- 功能列表 + 当前热键
- 修改按钮进入监听模式
- 冲突提示

---

## 8. HelperStart 联动
### 8.1 行为
- `HelperStart.exe` 默认不启动 GUI
- `HelperStart_GUI.exe` 默认启动 GUI（按名称包含 `_GUI`）
- `[gui]` 配置可覆盖默认

### 8.2 配置建议
```
[gui]
gui_path=GameHelperGUI.exe
```

---

## 9. 关键边界与错误处理
- 共享内存不存在：显示“未连接”
- 版本不匹配：显示“版本不兼容”
- INI 不存在：提示并允许创建
- 参数越界：GUI 阻止输入并提示

---

## 10. 实施计划（任务拆分）
### 10.1 GUI 端（WPF）
1. 建工程与目录结构
2. 共享内存读取模块（带版本校验）
3. INI 读写模块
4. JSON 元数据解析与表单生成
5. 热键绑定交互组件
6. 三页 UI 与数据绑定
7. 基本异常提示与状态显示

### 10.2 DLL 端（version-inject）
1. 定义并维护共享内存结构体
2. 定时写入状态（200~500ms）
3. 填充目标状态/当前状态/功能状态字段
4. 版本号与结构体大小写入

### 10.3 联调与验证
1. GUI 识别在线/离线
2. 版本不匹配提示
3. INI 修改后重启生效验证
4. 热键绑定写入正确性验证

---

## 11. 验收要点
- GUI 可稳定读取共享内存状态
- 三页可正常展示与编辑
- 热键绑定可改且生效（重启后）
- 参数配置能覆盖所有可配置项
- 版本不兼容提示准确
