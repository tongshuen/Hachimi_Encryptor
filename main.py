import sys
import argparse
import zlib
from tkinter import Tk, Frame, Label, Text, Entry, Button, StringVar, Radiobutton, messagebox, scrolledtext

# 哈基米字符集
HKM_CHARS = ['哈', '基', '米', '咪', '~', '～', 'h', 'j', 'm']

def xor_encrypt(text: str, key: str) -> str:
    """XOR加密/解密（密钥可任意长度）"""
    if not key:
        key = 'default_key'
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def compress_data(data: str) -> bytes:
    """压缩数据，自动判断是否压缩"""
    original_bytes = data.encode('utf-8')
    compressed = zlib.compress(original_bytes)
    return compressed if len(compressed) < len(original_bytes) else b'\x00' + original_bytes

def decompress_data(compressed_data: bytes) -> str:
    """解压缩数据"""
    if compressed_data.startswith(b'\x00'):
        return compressed_data[1:].decode('utf-8')
    return zlib.decompress(compressed_data).decode('utf-8')

def bytes_to_hkm(byte_data: bytes) -> str:
    """字节→哈基米密文（1字节→2字符）"""
    hkm_text = []
    for byte in byte_data:
        high, low = divmod(byte, 9)  # 9进制拆分
        hkm_text.append(HKM_CHARS[high])
        hkm_text.append(HKM_CHARS[low])
    return ''.join(hkm_text)

def hkm_to_bytes(hkm_text: str) -> bytes:
    """哈基米密文→字节"""
    byte_list = []
    for i in range(0, len(hkm_text), 2):
        high = HKM_CHARS.index(hkm_text[i])
        low = HKM_CHARS.index(hkm_text[i+1])
        byte_list.append(high * 9 + low)
    return bytes(byte_list)

def encode_text(text: str, key: str) -> str:
    """编码文本→哈基米密文"""
    try:
        encrypted = xor_encrypt(text, key)
        compressed = compress_data(encrypted)
        return bytes_to_hkm(compressed)
    except Exception as e:
        return f"编码错误: {str(e)}"

def decode_text(hkm_text: str, key: str) -> str:
    """哈基米密文→原始文本"""
    try:
        byte_data = hkm_to_bytes(hkm_text)
        encrypted = decompress_data(byte_data)
        return xor_encrypt(encrypted, key)
    except Exception as e:
        return f"解码错误: {str(e)}"

def validate_hkm_text(text: str) -> bool:
    """验证是否为合法哈基米密文"""
    return all(c in HKM_CHARS for c in text)

class HKMApp:
    """GUI界面"""
    def __init__(self, root):
        self.root = root
        root.title("哈基米加密器 ©2025 童顺")
        root.geometry("600x500")
        
        # 模式选择
        self.mode = StringVar(value="encode")
        frame_mode = Frame(root)
        frame_mode.pack(pady=10)
        Radiobutton(frame_mode, text="编码模式", variable=self.mode, 
                   value="encode", command=self.update_ui).pack(side="left", padx=10)
        Radiobutton(frame_mode, text="解码模式", variable=self.mode, 
                   value="decode", command=self.update_ui).pack(side="left", padx=10)
        
        # 编码UI
        self.frame_encode = Frame(root)
        Label(self.frame_encode, text="输入要编码的文本:").pack(anchor="w")
        self.encode_input = scrolledtext.ScrolledText(self.frame_encode, height=8)
        self.encode_input.pack(fill="x", pady=5)
        Label(self.frame_encode, text="密钥:").pack(anchor="w")
        self.encode_key = Entry(self.frame_encode)
        self.encode_key.pack(fill="x", pady=5)
        Button(self.frame_encode, text="编码", command=self.do_encode).pack(pady=10)
        Label(self.frame_encode, text="编码结果:").pack(anchor="w")
        self.encode_result = scrolledtext.ScrolledText(self.frame_encode, height=8, state="disabled")
        self.encode_result.pack(fill="x", pady=5)
        
        # 解码UI
        self.frame_decode = Frame(root)
        Label(self.frame_decode, text="输入要解码的密文:").pack(anchor="w")
        self.decode_input = scrolledtext.ScrolledText(self.frame_decode, height=8)
        self.decode_input.pack(fill="x", pady=5)
        Label(self.frame_decode, text="密钥:").pack(anchor="w")
        self.decode_key = Entry(self.frame_decode)
        self.decode_key.pack(fill="x", pady=5)
        Button(self.frame_decode, text="解码", command=self.do_decode).pack(pady=10)
        Label(self.frame_decode, text="解码结果:").pack(anchor="w")
        self.decode_result = scrolledtext.ScrolledText(self.frame_decode, height=8, state="disabled")
        self.decode_result.pack(fill="x", pady=5)
        
        self.update_ui()
    
    def update_ui(self):
        """切换模式"""
        if self.mode.get() == "encode":
            self.frame_encode.pack(fill="both", expand=True, padx=20)
            self.frame_decode.pack_forget()
        else:
            self.frame_encode.pack_forget()
            self.frame_decode.pack(fill="both", expand=True, padx=20)
    
    def do_encode(self):
        """执行编码"""
        text = self.encode_input.get("1.0", "end-1c")
        key = self.encode_key.get()
        if not text:
            messagebox.showerror("错误", "请输入文本")
            return
        
        result = encode_text(text, key)
        self.encode_result.config(state="normal")
        self.encode_result.delete("1.0", "end")
        self.encode_result.insert("1.0", result)
        self.encode_result.config(state="disabled")
        
        # 显示压缩率
        orig_size = len(text.encode('utf-8'))
        compressed_size = len(result) / 2  # 1字节→2字符
        messagebox.showinfo("完成", f"原始: {orig_size}字节\n密文: {len(result)}字符\n压缩率: {compressed_size/orig_size:.1%}")
    
    def do_decode(self):
        """执行解码"""
        text = self.decode_input.get("1.0", "end-1c").strip()
        key = self.decode_key.get()
        if not text:
            messagebox.showerror("错误", "请输入密文")
            return
        if not validate_hkm_text(text):
            messagebox.showerror("错误", "密文只能包含: " + ' '.join(HKM_CHARS))
            return
        
        result = decode_text(text, key)
        self.decode_result.config(state="normal")
        self.decode_result.delete("1.0", "end")
        self.decode_result.insert("1.0", result)
        self.decode_result.config(state="disabled")

def cli_main():
    """命令行模式"""
    parser = argparse.ArgumentParser(description="哈基米加密器 ©2025 童顺")
    parser.add_argument("mode", choices=["encode", "decode"], help="模式")
    parser.add_argument("-t", "--text", help="直接输入文本")
    parser.add_argument("-f", "--file", help="从文件读取")
    parser.add_argument("-k", "--key", required=True, help="密钥")
    parser.add_argument("-o", "--output", help="输出文件")
    args = parser.parse_args()
    
    # 获取输入
    text = args.text or (open(args.file, 'r', encoding='utf-8').read() if args.file else None)
    if not text:
        print("错误: 需要 -t 或 -f 参数")
        sys.exit(1)
    
    # 执行操作
    if args.mode == "encode":
        result = encode_text(text, args.key)
        print("编码结果:\n" + result)
    else:
        if not validate_hkm_text(text):
            print("错误: 密文包含非法字符")
            sys.exit(1)
        result = decode_text(text, args.key)
        print("解码结果:\n" + result)
    
    # 输出到文件
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"结果已保存到: {args.output}")

if __name__ == "__main__":
    if "--no-gui" in sys.argv:
        sys.argv.remove("--no-gui")
        cli_main()
    else:
        try:
            root = Tk()
            HKMApp(root)
            root.mainloop()
        except ImportError:
            print("GUI 不可用，已切换到 CLI")
            cli_main()
