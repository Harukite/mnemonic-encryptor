import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import io
import qrcode
from mnemonic_encryptor import encrypt_mnemonic, decrypt_mnemonic
import json
import os

class MnemonicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('助记词加密工具')
        self.root.geometry('500x350')
        # 禁用窗口大小调整
        self.root.resizable(False, False)
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置主窗口的网格权重，使其自适应
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        
        # 配置主框架的网格权重
        self.main_frame.grid_columnconfigure(1, weight=1)
        
        # 模式选择
        self.mode_var = tk.StringVar(value='encrypt')
        ttk.Label(self.main_frame, text='选择操作模式：').grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Radiobutton(self.main_frame, text='加密', value='encrypt', variable=self.mode_var, command=self.switch_mode).grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text='解密', value='decrypt', variable=self.mode_var, command=self.switch_mode).grid(row=0, column=2, sticky=tk.W)
        
        # TOTP 选项
        self.use_totp_var = tk.BooleanVar(value=True)
        self.totp_check = ttk.Checkbutton(self.main_frame, text='使用动态码验证（推荐）', variable=self.use_totp_var)
        self.totp_check.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=5)
        
        # 助记词输入/输出
        self.mnemonic_label = ttk.Label(self.main_frame, text='输入助记词（用空格分隔）：')
        self.mnemonic_label.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.mnemonic_text = tk.Text(self.main_frame, height=3)
        self.mnemonic_text.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # 密码输入
        ttk.Label(self.main_frame, text='输入密码：').grid(row=4, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(self.main_frame, show='*')
        self.password_entry.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 确认密码（加密模式）
        self.confirm_label = ttk.Label(self.main_frame, text='确认密码：')
        self.confirm_label.grid(row=5, column=0, sticky=tk.W, pady=5)
        self.confirm_entry = ttk.Entry(self.main_frame, show='*')
        self.confirm_entry.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 文件选择（解密模式）
        self.file_frame = ttk.Frame(self.main_frame)
        self.file_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        self.file_label = ttk.Label(self.file_frame, text='选择加密文件：')
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, state='readonly')
        self.file_button = ttk.Button(self.file_frame, text='浏览...', command=self.browse_file)
        
        # TOTP 验证码输入
        self.totp_frame = ttk.Frame(self.main_frame)
        self.totp_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        self.totp_label = ttk.Label(self.totp_frame, text='输入动态验证码：')
        self.totp_entry = ttk.Entry(self.totp_frame)
        
        # QR码显示区域
        self.qr_frame = ttk.Frame(self.main_frame)
        self.qr_frame.grid(row=8, column=0, columnspan=3, pady=10)
        self.qr_label = ttk.Label(self.qr_frame)
        
        # 操作按钮
        self.action_button = ttk.Button(self.main_frame, text='加密', command=self.process)
        self.action_button.grid(row=9, column=0, columnspan=3, pady=10)
        
        # 初始化界面
        self.switch_mode()
        
    def switch_mode(self):
        mode = self.mode_var.get()
        
        # 清除所有输入
        self.mnemonic_text.configure(state='normal')
        self.mnemonic_text.delete('1.0', tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)
        self.totp_entry.delete(0, tk.END)
        self.file_path_var.set('')
        
        # 清除QR码显示
        self.qr_label.grid_remove()
        
        if mode == 'encrypt':
            self.action_button.configure(text='加密')
            self.mnemonic_label.configure(text='输入助记词（用空格分隔）：')
            self.confirm_label.grid()
            self.confirm_entry.grid()
            self.file_label.grid_remove()
            self.file_entry.grid_remove()
            self.file_button.grid_remove()
            self.totp_check.configure(state='normal')
            self.mnemonic_text.configure(state='normal')
        else:
            self.action_button.configure(text='解密')
            self.mnemonic_label.configure(text='解密结果：')
            self.confirm_label.grid_remove()
            self.confirm_entry.grid_remove()
            self.file_label.grid(row=0, column=0, sticky=tk.W)
            self.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
            self.file_button.grid(row=0, column=2, sticky=tk.W)
            self.mnemonic_text.configure(state='disabled')
            
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title='选择加密文件',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')]
        )
        if file_path:
            self.file_path_var.set(file_path)
            # 读取文件检查是否包含TOTP
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    has_totp = 'totp' in data
                    self.use_totp_var.set(has_totp)
                    self.totp_check.configure(state='disabled')
            except Exception as e:
                messagebox.showerror('错误', f'读取文件失败：{str(e)}')
                
    def show_qr_code(self, uri):
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make()
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 转换为PhotoImage
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        image = Image.open(io.BytesIO(img_byte_arr))
        photo = ImageTk.PhotoImage(image)
        
        self.qr_label.configure(image=photo)
        self.qr_label.image = photo  # 保持引用
        self.qr_label.grid()
        
    def validate_password(self, password):
        if len(password) < 6:
            return False, '密码长度不能少于6位'
        if len(password) > 50:
            return False, '密码长度不能超过50位'
        
        # 检查密码复杂度
        has_digit = any(c.isdigit() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        complexity_score = sum([has_digit, has_upper, has_lower, has_special])
        if complexity_score < 3:
            return False, '密码必须包含数字、大写字母、小写字母、特殊字符中的至少3种'
            
        return True, ''
    
    def process(self):
        mode = self.mode_var.get()
        password = self.password_entry.get()
        use_totp = self.use_totp_var.get()
        
        if not password:
            messagebox.showerror('错误', '请输入密码')
            return
            
        if mode == 'encrypt':
            # 验证密码强度
            is_valid, error_msg = self.validate_password(password)
            if not is_valid:
                messagebox.showerror('错误', error_msg)
                return
            
        try:
            if mode == 'encrypt':
                # 加密模式
                if password != self.confirm_entry.get():
                    messagebox.showerror('错误', '两次输入的密码不一致')
                    return
                    
                mnemonic = self.mnemonic_text.get('1.0', tk.END).strip()
                if not mnemonic:
                    messagebox.showerror('错误', '请输入助记词')
                    return
                    
                # 清除现有的QR码显示
                self.qr_label.grid_remove()
                
                # 显示TOTP输入框（如果启用）
                if use_totp:
                    self.totp_label.grid(row=0, column=0, sticky=tk.W)
                    self.totp_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
                    self.totp_entry.focus()
                else:
                    self.totp_label.grid_remove()
                    self.totp_entry.grid_remove()
                    
                try:
                    enc = encrypt_mnemonic(mnemonic, password, use_totp)
                    file_path = filedialog.asksaveasfilename(
                        defaultextension='.json',
                        filetypes=[('JSON files', '*.json')],
                        initialfile='mnemonic.enc.json'
                    )
                    if file_path:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            json.dump(enc, f, ensure_ascii=False, indent=2)
                        # 清除助记词并禁用撤销功能
                        self.mnemonic_text.delete('1.0', tk.END)
                        self.mnemonic_text.edit_reset()  # 清除撤销/重做历史
                        messagebox.showinfo('成功', f'加密完成，文件已保存到：{file_path}')
                except Exception as e:
                    messagebox.showerror('错误', str(e))
                    
            else:
                # 解密模式
                file_path = self.file_path_var.get()
                if not file_path:
                    messagebox.showerror('错误', '请选择加密文件')
                    return
                    
                if not os.path.exists(file_path):
                    messagebox.showerror('错误', '文件不存在')
                    return
                    
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        enc = json.load(f)
                    
                    mnemonic = decrypt_mnemonic(enc, password, use_totp)
                    self.mnemonic_text.configure(state='normal')
                    self.mnemonic_text.delete('1.0', tk.END)
                    self.mnemonic_text.insert('1.0', mnemonic)
                    self.mnemonic_text.configure(state='disabled')
                    messagebox.showinfo('成功', '解密完成')
                except Exception as e:
                    messagebox.showerror('错误', str(e))
                    
        except Exception as e:
            messagebox.showerror('错误', str(e))
            
        finally:
            # 清除密码输入
            self.password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)
            self.totp_entry.delete(0, tk.END)

def main():
    root = tk.Tk()
    app = MnemonicGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
