#include <iostream>     // 输入输出
#include <fstream>      // 文件流
#include <string>       // 字符串
#include <vector>       // 动态数组
#include <map>          // 键值对映射
#include <queue>        // 优先队列
#include <algorithm>    // 算法（如min, reverse）
#include <bitset>       // 位操作（用于调试查看位串）
#include <iomanip>      // 格式化输出
#include <limits>       // 用于 std::numeric_limits
#include <functional>   // 用于 std::hash

// Windows API 相关的头文件
#include <windows.h>
#include <shlwapi.h>    // PathFindExtensionW, PathFindFileNameW

// 定义Huffman压缩文件的默认后缀名
const std::string HUFF_EXT = ".huf";

// ====================================================================
// 1. Huffman 树节点结构
// ====================================================================
struct HuffmanNode {
    char data;          // 存储字符（叶子节点使用）
    int freq;           // 频率
    HuffmanNode *left;  // 左子节点
    HuffmanNode *right; // 右子节点

    // 叶子节点构造函数
    HuffmanNode(char data, int freq) : data(data), freq(freq), left(nullptr), right(nullptr) {}

    // 内部节点构造函数
    HuffmanNode(int freq, HuffmanNode* left, HuffmanNode* right)
        : data('\0'), freq(freq), left(left), right(right) {}

    // 析构函数：释放子节点内存，防止内存泄漏
    ~HuffmanNode() {
        delete left;
        delete right;
    }
};

// 用于优先队列的比较器：频率小的节点优先级高（构建小顶堆）
struct CompareNodes {
    bool operator()(HuffmanNode* a, HuffmanNode* b) {
        return a->freq > b->freq;
    }
};

// ====================================================================
// 2. 简易加密/解密类 (XOR 加密)
// ====================================================================
class SimpleXORCipher {
public:
    // 使用密码作为密钥流进行XOR加密/解密
        std::vector<unsigned char> encryptDecrypt(const std::vector<unsigned char>& data, const std::string& password) {
        std::vector<unsigned char> result = data;
        if (password.empty() || data.empty()) {
            return data; // 如果密码为空或数据为空，不进行加密
        }

        size_t passwordLen = password.length();
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ static_cast<unsigned char>(password[i % passwordLen]);
        }
        return result;
    }
};

// ====================================================================
// 4. 文件管理和工具类 (提前定义，因为 HuffmanCodec 需要使用其静态方法)
// ====================================================================
class FileManager {
public:
    // 设置控制台编码为UTF-8
    void setConsoleUTF8() {
        // 设置控制台输出代码页为UTF-8
        if (!SetConsoleOutputCP(CP_UTF8)) {
            std::cerr << "警告: 无法设置控制台输出为UTF-8 (错误码: " << GetLastError() << ")" << std::endl;
        }
        // 设置控制台输入代码页为UTF-8
        if (!SetConsoleCP(CP_UTF8)) {
            std::cerr << "警告: 无法设置控制台输入为UTF-8 (错误码: " << GetLastError() << ")" << std::endl;
        }
    }

    // 将UTF-8 std::string 转换为宽字符 std::wstring (用于Windows API)
    static std::wstring Utf8ToWideChar(const std::string& utf8str) {
        if (utf8str.empty()) return L"";
        // 计算所需宽字符缓冲区大小
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), (int)utf8str.length(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        // 执行转换
        MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), (int)utf8str.length(), &wstrTo[0], size_needed);
        return wstrTo;
    }

    // 将宽字符 std::wstring 转换为UTF-8 std::string
    static std::string WideCharToUtf8(const WCHAR* wstr) {
        if (!wstr) return "";
        // 计算所需UTF-8缓冲区大小
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL); // -1表示wstr以null结尾
        if (size_needed == 0) return ""; // 转换失败或字符串为空
        std::string utf8str(size_needed - 1, '\0'); // 减1因为不包含null terminator
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &utf8str[0], size_needed, NULL, NULL);
        return utf8str;
    }

    // 获取当前目录下的所有文件列表
    std::vector<std::string> listFilesInCurrentDirectory() {
        std::vector<std::string> fileList;
        WIN32_FIND_DATAW findData; // 使用宽字符结构体

        // 查找当前目录下的所有文件和目录
        HANDLE hFind = FindFirstFileW(L".\\*", &findData); // L".\\*" 表示当前目录下所有
        if (hFind == INVALID_HANDLE_VALUE) {
            std::cerr << "错误: 无法获取当前目录文件列表 (错误码: " << GetLastError() << ")" << std::endl;
            return fileList;
        }

        do {
            // 跳过 "." 和 ".."
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
                continue;
            }

            // 过滤掉目录、隐藏文件、系统文件
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ||
                (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)) {
                continue;
            }

            // 将宽字符文件名转换为UTF-8 std::string
            fileList.push_back(FileManager::WideCharToUtf8(findData.cFileName));
        } while (FindNextFileW(hFind, &findData) != 0);

        FindClose(hFind);
        return fileList;
    }

    // 获取文件大小
    long long getFileSize(const std::string& filename) {
        // 使用宽字符路径打开文件，以支持中文和特殊字符路径
        std::ifstream file(FileManager::Utf8ToWideChar(filename).c_str(), std::ios::binary | std::ios::ate); // ate: 定位到文件末尾
        if (!file.is_open()) {
            return -1; // 文件不存在或无法打开
        }
        long long size = file.tellg(); // 获取当前文件指针位置（即文件大小）
        file.close();
        return size;
    }

    // 获取文件扩展名 (包含点，例如 ".txt")
    std::string getFileExtension(const std::string& filename) {
        std::wstring wFilename = FileManager::Utf8ToWideChar(filename);
        const WCHAR* ext = PathFindExtensionW(wFilename.c_str());
        if (ext && *ext != L'\0') { // 确保找到了扩展名且不为空字符串
            return FileManager::WideCharToUtf8(ext);
        }
        return ""; // 没有扩展名则返回空字符串
    }

    // 从完整路径中提取文件名（不含路径部分）
    std::string getBaseFilename(const std::string& fullPath) {
        std::wstring wFullPath = FileManager::Utf8ToWideChar(fullPath);
        const WCHAR* wBaseName = PathFindFileNameW(wFullPath.c_str());
        if (wBaseName) {
            return FileManager::WideCharToUtf8(wBaseName);
        }
        return fullPath; // 如果无法解析，返回原路径（作为后备）
    }

    // 写入压缩文件
    bool writeCompressedFile(const std::string& outputPath,
                             const std::string& originalFilenameInHeader, // 仅文件名部分
                             const std::string& originalExtensionInHeader, // 扩展名部分
                             long long originalFileSize,
                             int paddingBits,
                             bool isPasswordProtected,
                             const std::map<char, std::string>& huffmanCodes,
                             const std::vector<unsigned char>& compressedBytes) {
        // 使用宽字符路径创建文件，以支持中文和特殊字符路径
        std::ofstream outputFile(FileManager::Utf8ToWideChar(outputPath).c_str(), std::ios::binary);
        if (!outputFile.is_open()) {
            std::cerr << "错误: 无法创建压缩文件 '" << outputPath << "'\n";
            return false;
        }

        // 1. 写入原始文件名长度 (UTF-8字节长度)
        size_t originalNameLen = originalFilenameInHeader.length();
        outputFile.write(reinterpret_cast<const char*>(&originalNameLen), sizeof(originalNameLen));
        // 2. 写入原始文件名 (UTF-8编码)
        outputFile.write(originalFilenameInHeader.c_str(), originalNameLen);

        // 3. 写入原始文件扩展名长度 (UTF-8字节长度)
        size_t originalExtLen = originalExtensionInHeader.length();
        outputFile.write(reinterpret_cast<const char*>(&originalExtLen), sizeof(originalExtLen));
        // 4. 写入原始文件扩展名 (UTF-8编码)
        outputFile.write(originalExtensionInHeader.c_str(), originalExtLen);

        // 5. 写入原始文件大小
        outputFile.write(reinterpret_cast<const char*>(&originalFileSize), sizeof(originalFileSize));

        // 6. 写入填充比特数
        outputFile.write(reinterpret_cast<const char*>(&paddingBits), sizeof(paddingBits));

        // 7. 写入是否密码保护
        outputFile.write(reinterpret_cast<const char*>(&isPasswordProtected), sizeof(isPasswordProtected));

        // 8. 写入Huffman编码表大小
        size_t mapSize = huffmanCodes.size();
        outputFile.write(reinterpret_cast<const char*>(&mapSize), sizeof(mapSize));

        // 9. 写入Huffman编码表
        for (auto const& [key, val] : huffmanCodes) {
            outputFile.write(reinterpret_cast<const char*>(&key), sizeof(key)); // 写入字符
            size_t codeLen = val.length();
            outputFile.write(reinterpret_cast<const char*>(&codeLen), sizeof(codeLen)); // 写入编码长度
            outputFile.write(val.c_str(), codeLen); // 写入编码字符串
        }

        // 10. 写入压缩数据
        if (!compressedBytes.empty()) {
            outputFile.write(reinterpret_cast<const char*>(compressedBytes.data()), compressedBytes.size());
        }

        outputFile.close();
        return true;
    }

    // 读取压缩文件头信息和编码表
    size_t readCompressedFileHeader(std::ifstream& inputFile,
                                    std::string& originalFilename,
                                    std::string& originalExtension,
                                    long long& originalFileSize,
                                    int& paddingBits,
                                    bool& isPasswordProtected,
                                    std::map<char, std::string>& huffmanCodes) {
        if (!inputFile.is_open()) {
            std::cerr << "错误: 文件流未打开，无法读取文件头。\n";
            return 0;
        }

        std::streampos startPos = inputFile.tellg(); // 记录开始位置

        // 1. 读取原始文件名长度
        size_t originalNameLen;
        inputFile.read(reinterpret_cast<char*>(&originalNameLen), sizeof(originalNameLen));
        if (inputFile.fail()) { std::cerr << "错误: 读取文件名长度失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }
        
        // 2. 读取原始文件名
        originalFilename.resize(originalNameLen);
        inputFile.read(&originalFilename[0], originalNameLen);
        if (inputFile.fail()) { std::cerr << "错误: 读取文件名失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 3. 读取原始文件扩展名长度
        size_t originalExtLen;
        inputFile.read(reinterpret_cast<char*>(&originalExtLen), sizeof(originalExtLen));
        if (inputFile.fail()) { std::cerr << "错误: 读取文件扩展名长度失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 4. 读取原始文件扩展名
        originalExtension.resize(originalExtLen);
        inputFile.read(&originalExtension[0], originalExtLen);
        if (inputFile.fail()) { std::cerr << "错误: 读取文件扩展名失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 5. 读取原始文件大小
        inputFile.read(reinterpret_cast<char*>(&originalFileSize), sizeof(originalFileSize));
        if (inputFile.fail()) { std::cerr << "错误: 读取原始文件大小失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 6. 读取填充比特数
        inputFile.read(reinterpret_cast<char*>(&paddingBits), sizeof(paddingBits));
        if (inputFile.fail()) { std::cerr << "错误: 读取填充比特数失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 7. 读取是否密码保护
        inputFile.read(reinterpret_cast<char*>(&isPasswordProtected), sizeof(isPasswordProtected));
        if (inputFile.fail()) { std::cerr << "错误: 读取密码保护标志失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 8. 读取Huffman编码表大小
        size_t mapSize;
        inputFile.read(reinterpret_cast<char*>(&mapSize), sizeof(mapSize));
        if (inputFile.fail()) { std::cerr << "错误: 读取编码表大小失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

        // 9. 读取Huffman编码表
        huffmanCodes.clear();
        for (size_t i = 0; i < mapSize; ++i) {
            char key;
            size_t codeLen;
            inputFile.read(reinterpret_cast<char*>(&key), sizeof(key)); // 读取字符
            if (inputFile.fail()) { std::cerr << "错误: 读取编码表字符失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }
            inputFile.read(reinterpret_cast<char*>(&codeLen), sizeof(codeLen)); // 读取编码长度
            if (inputFile.fail()) { std::cerr << "错误: 读取编码表长度失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }

            std::string code(codeLen, '\0');
            inputFile.read(&code[0], codeLen); // 读取编码字符串
            if (inputFile.fail()) { std::cerr << "错误: 读取编码表字符串失败. 流状态: " << inputFile.rdstate() << "\n"; return 0; }
            huffmanCodes[key] = code;
        }

        // 返回当前文件指针的位置，即头部总字节数
        return static_cast<size_t>(inputFile.tellg() - startPos);
    }

    // 读取压缩文件中的所有压缩数据 (从当前文件流位置读取到文件末尾)
    std::vector<unsigned char> readCompressedDataFromStream(std::ifstream& inputFile) {
        std::vector<unsigned char> compressedData;
        char byte;
        while (inputFile.get(byte)) {
            compressedData.push_back(static_cast<unsigned char>(byte));
        }
        return compressedData;
    }

    // 写入解压后的原始文件
    bool writeDecompressedFile(const std::string& outputPath, const std::vector<unsigned char>& decompressedBytes) {
        // 使用宽字符路径创建文件，以支持中文和特殊字符路径
        std::ofstream outputFile(FileManager::Utf8ToWideChar(outputPath).c_str(), std::ios::binary);
        if (!outputFile.is_open()) {
            std::cerr << "错误: 无法创建解压文件 '" << outputPath << "'\n";
            return false;
        }

        if (!decompressedBytes.empty()) {
            outputFile.write(reinterpret_cast<const char*>(decompressedBytes.data()), decompressedBytes.size());
        }

        outputFile.close();
        return true;
    }
};

// ====================================================================
// 3. 核心 Huffman 编码/解码逻辑类 (移到 FileManager 后面以确保其定义可见)
// ====================================================================
class HuffmanCodec {
public:
    HuffmanCodec() : root(nullptr) {}

    // 析构函数：确保释放Huffman树的内存
    ~HuffmanCodec() {
        // root的析构函数会自动递归删除所有子节点
        delete root;
    }

    // 步骤1: 统计文件中每个字节的频率
    std::map<char, int> getFrequencies(const std::string& filename) {
        std::map<char, int> frequencies;
        // FIX: 使用宽字符路径打开文件，并使用 FileManager 静态方法
        std::ifstream inputFile(FileManager::Utf8ToWideChar(filename).c_str(), std::ios::binary);

        if (!inputFile.is_open()) {
            std::cerr << "错误: 无法打开文件 '" << filename << "' 进行频率统计。" << std::endl;
            return frequencies;
        }

        char byte;
        while (inputFile.get(byte)) {
            frequencies[byte]++;
        }
        inputFile.close();
        return frequencies;
    }

    // 步骤2: 根据频率构建Huffman树
    void buildHuffmanTree(const std::map<char, int>& frequencies) {
        // 清理旧的Huffman树（如果存在）
        delete root;
        root = nullptr;

        std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, CompareNodes> pq;

        // 将所有字符作为叶子节点加入优先队列
        for (auto const& [key, val] : frequencies) {
            pq.push(new HuffmanNode(key, val));
        }

        // 如果文件是空的，或者只有一个字符（特殊处理）
        if (pq.empty()) {
            std::cerr << "警告: 文件内容为空，无法构建Huffman树。" << std::endl;
            return;
        }
        if (pq.size() == 1) {
            root = pq.top();
            pq.pop();
            huffmanCodes[root->data] = "0"; // 规定单个字符的编码为"0"
            return;
        }

        // 循环直到队列中只剩一个节点（即根节点）
        while (pq.size() > 1) {
            HuffmanNode* left = pq.top();
            pq.pop();
            HuffmanNode* right = pq.top();
            pq.pop();

            // 创建新的内部节点，其频率为两个子节点频率之和
            HuffmanNode* parent = new HuffmanNode(left->freq + right->freq, left, right);
            pq.push(parent);
        }

        root = pq.top(); // 最终剩下的就是Huffman树的根节点
        pq.pop();

        // 步骤3: 生成Huffman编码表
        generateCodes(root, "");
    }

    // 获取Huffman编码表
    const std::map<char, std::string>& getHuffmanCodes() const {
        return huffmanCodes;
    }

    // 编码文件内容并返回压缩后的字节向量和填充比特数
    std::pair<std::vector<unsigned char>, int> encodeFile(const std::string& filename) {
        // FIX: 使用宽字符路径打开文件，并使用 FileManager 静态方法
        std::ifstream inputFile(FileManager::Utf8ToWideChar(filename).c_str(), std::ios::binary);
        if (!inputFile.is_open()) {
            std::cerr << "错误: 无法打开文件 '" << filename << "' 进行编码。" << std::endl;
            return {{}, 0};
        }

        std::string bitBuffer = ""; // 用于累积所有编码后的比特流

        char byte;
        while (inputFile.get(byte)) {
            if (huffmanCodes.count(byte)) {
                bitBuffer += huffmanCodes[byte];
            } else {
                // 这可能发生在文件为空时，或者如果文件中有在频率统计后没有编码的字符（不应发生）
                std::cerr << "错误: 文件中包含未在Huffman树中编码的字符。请检查文件内容或频率统计。\n";
                inputFile.close();
                return {{}, 0};
            }
        }
        inputFile.close();

        // 计算需要填充的比特数，使总比特数为8的倍数
        int paddingBits = 0;
        if (bitBuffer.length() % 8 != 0) {
            paddingBits = 8 - (bitBuffer.length() % 8);
        }
        // 进行填充，通常用'0'填充
        for (int i = 0; i < paddingBits; ++i) {
            bitBuffer += '0';
        }

        // 将比特流打包成字节
        std::vector<unsigned char> compressedBytes;
        for (size_t i = 0; i < bitBuffer.length(); i += 8) {
            unsigned char currentByte = 0;
            for (int j = 0; j < 8; ++j) {
                if (bitBuffer[i + j] == '1') {
                    currentByte |= (1 << (7 - j)); // 从最高位开始填充
                }
            }
            compressedBytes.push_back(currentByte);
        }

        return {compressedBytes, paddingBits};
    }

    // 解码字节向量并返回原始数据，精确控制解码字节数
    std::vector<unsigned char> decodeBytes(const std::vector<unsigned char>& compressedBytes, int paddingBits, long long originalFileSize) {
        if (!root) {
            std::cerr << "错误: Huffman树为空，无法解码。\n";
            return {};
        }

        std::string bitStream = "";
        for (unsigned char byte : compressedBytes) {
            bitStream += std::bitset<8>(byte).to_string(); // 将每个字节转换为8位二进制字符串
        }

        // 移除末尾的填充比特
        if (paddingBits > 0 && bitStream.length() >= static_cast<size_t>(paddingBits)) {
            bitStream.resize(bitStream.length() - paddingBits);
        } else if (paddingBits > 0 && bitStream.length() < static_cast<size_t>(paddingBits)) {
            std::cerr << "警告: 填充位数与实际比特流长度不匹配。可能导致解码错误。\n";
            return {};
        }

        std::vector<unsigned char> decodedData;
        decodedData.reserve(originalFileSize); // 预分配内存，提高效率
        HuffmanNode* currentNode = root;

        for (char bit : bitStream) {
            if (static_cast<long long>(decodedData.size()) >= originalFileSize) {
                // 已解码足够多的字节，提前终止
                break;
            }

            if (!currentNode) { // 防止空指针解引用，理论上不会发生
                std::cerr << "解码错误: 当前节点为空，比特流解析异常。\n";
                return {};
            }

            if (bit == '0') {
                currentNode = currentNode->left;
            } else { // bit == '1'
                currentNode = currentNode->right;
            }

            if (!currentNode) { // 再次检查，防止在移动后变为nullptr
                std::cerr << "解码错误: 无法根据比特流找到下一个节点。可能数据损坏或密码错误。\n";
                return {};
            }

            // 如果到达叶子节点，则找到了一个字符
            if (currentNode->left == nullptr && currentNode->right == nullptr) {
                decodedData.push_back(currentNode->data);
                currentNode = root; // 重置到根节点，继续下一个字符的解码
            }
        }
        
        // 最终检查：解码的数据量是否与原始文件大小匹配
        if (static_cast<long long>(decodedData.size()) != originalFileSize) {
            std::cerr << "警告: 解码后数据大小(" << decodedData.size() 
                      << ")与原始文件大小(" << originalFileSize << ")不匹配。这可能意味着数据损坏、密码错误或文件头信息有误。\n";
        }
        return decodedData;
    }

    // 设置Huffman树根和编码表（用于从文件加载时重建）
    void setHuffmanTreeAndCodes(HuffmanNode* newRoot, const std::map<char, std::string>& codes) {
        // 释放现有树（如果存在）
        delete root;
        root = newRoot;
        huffmanCodes = codes;
    }

private:
    HuffmanNode* root;                      // Huffman树的根节点
    std::map<char, std::string> huffmanCodes; // 字符到其Huffman编码的映射

    // 递归生成Huffman编码表
    void generateCodes(HuffmanNode* node, std::string currentCode) {
        if (node == nullptr) {
            return;
        }

        // 如果是叶子节点，则将当前编码添加到映射中
        if (node->left == nullptr && node->right == nullptr) {
            huffmanCodes[node->data] = currentCode;
        }

        // 递归遍历左右子树
        generateCodes(node->left, currentCode + "0");
        generateCodes(node->right, currentCode + "1");
    }
};

// ====================================================================
// 5. 应用程序主类
// ====================================================================
class HuffmanApp {
public:
    HuffmanApp() {
        fileManager.setConsoleUTF8(); // 初始化时设置控制台编码
    }

    void run() {
        int choice;
        do {
            displayMenu();
            std::cout << "请输入您的选择: ";
            std::cin >> choice;

            // 检查输入是否为有效数字
            if (std::cin.fail()) {
                std::cin.clear(); // 清除错误标志
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // 忽略无效输入
                std::cout << "输入无效，请重新输入数字选项。\n";
                continue;
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // 清除输入缓冲区剩余内容

            switch (choice) {
                case 1:
                    compressFile();
                    break;
                case 2:
                    decompressFile();
                    break;
                case 3:
                    std::cout << "程序退出。感谢使用！\n";
                    break;
                default:
                    std::cout << "无效的选择，请重新输入。\n";
                    break;
            }
            std::cout << std::endl;
        } while (choice != 3);
    }

private:
    FileManager fileManager;
    HuffmanCodec huffmanCodec;
    SimpleXORCipher xorCipher; // 新增加密解密对象

    void displayMenu() {
        std::cout << "=======================================\n";
        std::cout << "  基于Huffman编码的文件压缩/解压缩软件  \n";
        std::cout << "=======================================\n";
        std::cout << "1. 压缩文件\n";
        std::cout << "2. 解压缩文件\n";
        std::cout << "3. 退出\n";
        std::cout << "---------------------------------------\n";
    }

    void displayFiles(const std::vector<std::string>& files) {
        if (files.empty()) {
            std::cout << "当前目录下没有可操作的文件。\n";
            return;
        }
        std::cout << "当前目录文件列表:\n";
        std::cout << "---------------------------------------\n";
        for (size_t i = 0; i < files.size(); ++i) {
            long long fileSize = fileManager.getFileSize(files[i]);
            std::string fileExtension = fileManager.getFileExtension(files[i]);
            if (fileExtension.empty()) fileExtension = "[无扩展名]";

            std::cout << std::setw(3) << i + 1 << ". "
                      << std::left << std::setw(40) << files[i]
                      << std::right << std::setw(15) << (fileSize != -1 ? std::to_string(fileSize) + " 字节" : "未知大小")
                      << "  类型: " << fileExtension
                      << std::endl;
        }
        std::cout << "---------------------------------------\n";
    }

    std::string getPasswordInput(const std::string& prompt) {
        std::string password;
        std::cout << prompt;
        // 注意：在Windows控制台，为了不显示密码，需要使用更底层的API，如_getch()。
        // 这里为了简化，直接使用getline，密码会显示。
        std::getline(std::cin, password);
        return password;
    }

    void compressFile() {
        std::cout << "\n--- 文件压缩 ---\n";
        std::vector<std::string> filesInDir = fileManager.listFilesInCurrentDirectory();
        displayFiles(filesInDir); 

        std::string inputPathStr;
        int selectedIndex = -1;

        std::cout << "请选择要压缩的文件序号 (1-" << filesInDir.size() << ") 或输入完整文件路径: ";
        std::string rawInput;
        std::getline(std::cin, rawInput);

        // 尝试将输入解析为数字序号
        try {
            // stoi 会抛出异常，这里捕获后进行路径处理
            size_t pos;
            int tempIndex = std::stoi(rawInput, &pos);
            if (pos == rawInput.length()) { // 确保整个字符串都是数字
                selectedIndex = tempIndex;
            }
        } catch (const std::invalid_argument& e) {
            // 输入不是数字，当作路径处理
        } catch (const std::out_of_range& e) {
            // 数字过大，当作路径处理
        }

        if (selectedIndex >= 1 && selectedIndex <= static_cast<int>(filesInDir.size())) {
            inputPathStr = filesInDir[selectedIndex - 1];
        } else {
            inputPathStr = rawInput; // 直接使用用户输入的路径
        }

        long long originalFileSize = fileManager.getFileSize(inputPathStr);
        if (originalFileSize == -1) {
            std::cout << "错误: 无法找到或打开文件 '" << inputPathStr << "'。\n";
            return;
        }
        if (originalFileSize == 0) {
            std::cout << "警告: 文件 '" << inputPathStr << "' 是空的，无法压缩。\n";
            return;
        }

        // 获取要存储在文件头中的原始文件名和扩展名
        // originalFilenameForHeader 现在将是完整的原始文件名 (例如 "我的文档.docx")
        std::string originalFilenameForHeader = fileManager.getBaseFilename(inputPathStr);
        // originalExtensionForHeader 将是原始文件的扩展名 (例如 ".docx")
        std::string originalExtensionForHeader = fileManager.getFileExtension(originalFilenameForHeader);

        std::cout << "正在统计文件频率和构建Huffman树... (进度: 1/3)\n";
        std::map<char, int> frequencies = huffmanCodec.getFrequencies(inputPathStr);
        if (frequencies.empty()) {
            std::cout << "错误: 文件 '" << inputPathStr << "' 频率统计失败或文件内容为空。\n";
            return;
        }
        huffmanCodec.buildHuffmanTree(frequencies);
        if (huffmanCodec.getHuffmanCodes().empty()) {
            std::cout << "错误: Huffman编码表生成失败。\n";
            return;
        }
        
        std::cout << "正在编码文件... (进度: 2/3)\n";
        auto [compressedBytes, paddingBits] = huffmanCodec.encodeFile(inputPathStr);
        if (compressedBytes.empty() && originalFileSize > 0) { // 如果原始文件非空但压缩结果为空
            std::cout << "错误: 文件编码失败。\n";
            return;
        }

        // 密码保护功能
        bool isPasswordProtected = false;
        std::string password;
        std::cout << "是否为压缩文件设置密码? (y/n): ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "y" || choice == "Y") {
            isPasswordProtected = true;
            password = getPasswordInput("请输入密码: ");
            std::string confirmPassword = getPasswordInput("请再次输入密码确认: ");
            if (password != confirmPassword) {
                std::cout << "两次密码输入不一致。取消密码保护。\n";
                isPasswordProtected = false;
                password = "";
            } else {
                // 对压缩数据进行加密
                compressedBytes = xorCipher.encryptDecrypt(compressedBytes, password);
            }
        }

        // FIX: 正确生成默认输出文件名（去除原始扩展名再添加 .huf）
        std::string baseNameWithoutOriginalExtension;
        std::wstring wOriginalFilenameForHeader = FileManager::Utf8ToWideChar(originalFilenameForHeader);
        const WCHAR* wExtStart = PathFindExtensionW(wOriginalFilenameForHeader.c_str());

        // 如果找到了扩展名（wExtStart指向的不是空字符）
        if (wExtStart && *wExtStart != L'\0') {
            // 计算不含扩展名的部分长度
            size_t lengthWithoutExt = wExtStart - wOriginalFilenameForHeader.c_str();
            baseNameWithoutOriginalExtension = FileManager::WideCharToUtf8(wOriginalFilenameForHeader.substr(0, lengthWithoutExt).c_str());
        } else {
            // 没有扩展名，则裸名就是原始文件名
            baseNameWithoutOriginalExtension = originalFilenameForHeader;
        }
        
        std::string defaultOutputFilename = baseNameWithoutOriginalExtension + HUFF_EXT;
        std::string customOutputFilename;
        std::cout << "是否自定义压缩文件名? (y/n) [默认: " << defaultOutputFilename << "]: ";
        std::getline(std::cin, choice);

        if (choice == "y" || choice == "Y") {
            std::cout << "请输入自定义压缩文件名: ";
            std::getline(std::cin, customOutputFilename);
            if (customOutputFilename.empty()) {
                std::cout << "文件名不能为空，使用默认名称。\n";
                customOutputFilename = defaultOutputFilename;
            } else if (customOutputFilename.length() < HUFF_EXT.length() ||
                       customOutputFilename.substr(customOutputFilename.length() - HUFF_EXT.length()) != HUFF_EXT) {
                std::cout << "为兼容性考虑，已自动添加 '" << HUFF_EXT << "' 后缀。\n";
                customOutputFilename += HUFF_EXT;
            }
        } else {
            customOutputFilename = defaultOutputFilename;
        }

        std::cout << "正在写入压缩文件 '" << customOutputFilename << "'... (进度: 3/3)\n";
        if (fileManager.writeCompressedFile(customOutputFilename, originalFilenameForHeader, originalExtensionForHeader, originalFileSize,
                                            paddingBits, isPasswordProtected, huffmanCodec.getHuffmanCodes(), compressedBytes)) {
            long long compressedFileSize = fileManager.getFileSize(customOutputFilename);
            double compressionRatio = (double)compressedFileSize / originalFileSize;
            std::cout << "文件压缩成功!\n";
            std::cout << "原始文件大小: " << originalFileSize << " 字节\n";
            std::cout << "压缩文件大小: " << compressedFileSize << " 字节\n";
            std::cout << std::fixed << std::setprecision(2);
            std::cout << "压缩效率 (压缩文件大小/原始文件大小): " << compressionRatio * 100 << "%\n";
            std::cout << "节约空间: " << (1 - compressionRatio) * 100 << "%\n";

            // 对PDF、DOCX等文件压缩效率的说明
            //std::cout << "\n--- 注意 ---\n";
            //std::cout << "对于PDF、DOCX等文件，由于它们内部可能已包含压缩，\n";
            //std::cout << "使用Huffman编码可能不会显著减小文件大小，甚至可能略有增加。\n";
            //std::cout << "Huffman编码主要对文本等重复性高、数据模式明显的非压缩文件效果显著。\n";

        } else {
            std::cout << "文件压缩失败。\n";
        }
    }

    void decompressFile() {
        std::cout << "\n--- 文件解压缩 ---\n";
        std::vector<std::string> filesInDir = fileManager.listFilesInCurrentDirectory();
        
        // 筛选出 .huf 文件
        std::vector<std::string> hufFiles;
        for (const auto& file : filesInDir) {
            if (file.length() >= HUFF_EXT.length() &&
                file.substr(file.length() - HUFF_EXT.length()) == HUFF_EXT) {
                hufFiles.push_back(file);
            }
        }

        if (hufFiles.empty()) {
            std::cout << "当前目录下没有 " << HUFF_EXT << " 压缩文件。\n";
            return;
        }

        displayFiles(hufFiles); // 仅供参考

        std::string inputPathStr;
        int selectedIndex = -1;

        std::cout << "请选择要解压缩的 " << HUFF_EXT << " 文件序号 (1-" << hufFiles.size() << ") 或输入完整文件路径: ";
        std::string rawInput;
        std::getline(std::cin, rawInput);

        // 尝试将输入解析为数字序号
        try {
            size_t pos;
            int tempIndex = std::stoi(rawInput, &pos);
            if (pos == rawInput.length()) { // 确保整个字符串都是数字
                selectedIndex = tempIndex;
            }
        } catch (const std::invalid_argument& e) {
            // 输入不是数字，当作路径处理
        } catch (const std::out_of_range& e) {
            // 数字过大，当作路径处理
        }

        if (selectedIndex >= 1 && selectedIndex <= static_cast<int>(hufFiles.size())) {
            inputPathStr = hufFiles[selectedIndex - 1];
        } else {
            inputPathStr = rawInput; // 直接使用用户输入的路径
        }

        std::string originalFilenameFromHeader;
        std::string originalExtensionFromHeader; // 解压后文件后缀名
        long long originalFileSize;
        int paddingBits;
        bool isPasswordProtected; // 是否密码保护
        std::map<char, std::string> huffmanCodes;

        std::cout << "正在读取压缩文件 '" << inputPathStr << "' 的头信息和编码表... (进度: 1/3)\n";
        // 使用宽字符路径打开文件流
        std::ifstream inputFileStream(FileManager::Utf8ToWideChar(inputPathStr).c_str(), std::ios::binary);
        if (!inputFileStream.is_open()) {
            std::cerr << "错误: 无法打开压缩文件 '" << inputPathStr << "'。\n";
            return;
        }

        size_t headerSize = fileManager.readCompressedFileHeader(inputFileStream, originalFilenameFromHeader, originalExtensionFromHeader,
                                                                 originalFileSize, paddingBits, isPasswordProtected, huffmanCodes);
        if (headerSize == 0) {
            std::cout << "错误: 读取压缩文件头信息失败或文件已损坏。请检查文件是否为有效的" << HUFF_EXT << "文件。\n";
            inputFileStream.close();
            return;
        }

        // 从编码表重建Huffman树
        HuffmanNode* reconstructedRoot = buildTreeFromCodes(huffmanCodes);
        if (!reconstructedRoot) {
            std::cerr << "错误: 无法从编码表重建Huffman树。文件可能已损坏或编码表无效。\n";
            inputFileStream.close();
            return;
        }
        huffmanCodec.setHuffmanTreeAndCodes(reconstructedRoot, huffmanCodes);

        std::cout << "正在读取压缩数据... (进度: 2/3)\n";
        std::vector<unsigned char> compressedData = fileManager.readCompressedDataFromStream(inputFileStream);
        inputFileStream.close(); // 读取完毕，关闭文件流

        if (compressedData.empty() && originalFileSize > 0) { // 如果原始文件不为空，但压缩数据为空，则有问题
            std::cout << "错误: 读取压缩数据失败或压缩文件内容异常。\n";
            return;
        }

        // 密码验证
        if (isPasswordProtected) {
            std::cout << "此文件受密码保护。\n";
            int attempts = 0;
            const int MAX_ATTEMPTS = 3;
            bool passwordCorrect = false;
            while (attempts < MAX_ATTEMPTS && !passwordCorrect) {
                std::string enteredPassword = getPasswordInput("请输入密码: ");
                std::vector<unsigned char> decryptedAttempt = xorCipher.encryptDecrypt(compressedData, enteredPassword);
                
                // 密码验证策略：尝试用输入的密码解密并解码，如果解码出的数据长度与原始文件大小匹配，则认为密码正确。
                               std::vector<unsigned char> tempDecompressedBytes = huffmanCodec.decodeBytes(decryptedAttempt, paddingBits, originalFileSize);
                
                if (static_cast<long long>(tempDecompressedBytes.size()) == originalFileSize) {
                    passwordCorrect = true;
                    compressedData = decryptedAttempt; // 密码正确，使用解密后的数据
                    std::cout << "密码正确。\n";
                } else {
                    attempts++;
                    std::cout << "密码错误。剩余尝试次数: " << (MAX_ATTEMPTS - attempts) << "\n";
                }
            }

            if (!passwordCorrect) {
                std::cout << "密码尝试次数已用完，无法解压。\n";
                return;
            }
        }

        std::cout << "正在解码文件... (进度: 3/3)\n";
        std::vector<unsigned char> decompressedBytes = huffmanCodec.decodeBytes(compressedData, paddingBits, originalFileSize);
        if (decompressedBytes.empty() && originalFileSize > 0) {
            std::cout << "错误: 文件解码失败。\n";
            return;
        }
        // decodeBytes内部已经有大小检查和警告

        // 组合原始文件名和扩展名
        std::string defaultOutputFilename = originalFilenameFromHeader;
        // 如果文件头中存储的原始文件名不包含扩展名，而原始扩展名不为空，则应添加。
        // getFileExtension会返回包含"."的扩展名，如果defaultOutputFilename已经有扩展名，就跳过。
        if (!originalExtensionFromHeader.empty() && fileManager.getFileExtension(defaultOutputFilename).empty()) {
             defaultOutputFilename += originalExtensionFromHeader;
        }

        std::string customOutputFilename;
        std::cout << "是否自定义解压后的文件名? (y/n) [默认: " << defaultOutputFilename << "]: ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "y" || choice == "Y") {
            std::cout << "请输入自定义解压文件名: ";
            std::getline(std::cin, customOutputFilename);
            if (customOutputFilename.empty()) {
                std::cout << "文件名不能为空，使用默认名称。\n";
                customOutputFilename = defaultOutputFilename;
            }
        } else {
            customOutputFilename = defaultOutputFilename;
        }

        std::cout << "正在写入解压文件 '" << customOutputFilename << "'...\n";
        if (fileManager.writeDecompressedFile(customOutputFilename, decompressedBytes)) {
            std::cout << "文件解压缩成功!\n";
            std::cout << "解压文件大小: " << decompressedBytes.size() << " 字节\n";
        } else {
            std::cout << "文件解压缩失败。\n";
        }
    }

    // 从Huffman编码表重建Huffman树
    HuffmanNode* buildTreeFromCodes(const std::map<char, std::string>& huffmanCodes) {
        if (huffmanCodes.empty()) {
            return nullptr;
        }

        HuffmanNode* rootNode = new HuffmanNode('\0', 0); // 创建一个根节点

        // 特殊处理只有一个字符的情况：编码为"0"，树只有一个根节点。
        if (huffmanCodes.size() == 1 && huffmanCodes.begin()->second == "0") {
            rootNode->data = huffmanCodes.begin()->first;
            return rootNode;
        }

        for (auto const& [character, code] : huffmanCodes) {
            HuffmanNode* currentNode = rootNode;
            for (char bit : code) {
                if (bit == '0') {
                    if (currentNode->left == nullptr) {
                        currentNode->left = new HuffmanNode('\0', 0);
                    }
                    currentNode = currentNode->left;
                } else { // bit == '1'
                    if (currentNode->right == nullptr) {
                        currentNode->right = new HuffmanNode('\0', 0);
                    }
                    currentNode = currentNode->right;
                }
            }
            // 到达编码路径的末尾，将字符赋值给叶子节点
            currentNode->data = character;
        }
        return rootNode;
    }
};

// ====================================================================
// 6. 主函数
// ====================================================================
int main() {
    HuffmanApp app;
    app.run();
    return 0;
}