# hashcalc-clone
A Python Tkinter clone of HashCalc GUI supporting multiple hash algorithms and HMAC

## Screenshot

![HashCalc Clone Screenshot](HashCalcClone1.jpg)

## Setup Instructions

1. **Prerequisites**: Ensure you have Python 3.x installed on your system
2. **Clone the repository**:
   ```bash
   git clone https://github.com/cyborgsri/hashcalc-clone.git
   cd hashcalc-clone
   ```
3. **Install dependencies** (if any):
   ```bash
   pip install -r requirements.txt
   ```
   Note: This project uses standard Python libraries (tkinter, hashlib), so no external dependencies are required

4. **Run the application**:
   ```bash
   python hashcalc5.py
   ```

## Usage

1. **Launch the application**: Run `python hashcalc5.py` to open the HashCalc GUI
2. **Enter text or data**: Type or paste the data you want to hash in the input field
3. **Select hash algorithm**: Choose from various hash algorithms (MD5, SHA-1, SHA-256, SHA-512, etc.)
4. **Calculate hash**: Click the "Calculate" button to generate the hash
5. **View results**: The computed hash value will be displayed in the output field
6. **HMAC support**: Enable HMAC mode and provide a key for keyed-hash message authentication
7. **Copy results**: Copy the hash output to your clipboard for use in other applications
