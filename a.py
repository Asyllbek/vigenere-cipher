from pip._vendor.distlib.compat import raw_input

MAX_KEY_LENGTH_GUESS = 20
alphabet = 'abcdefghijklmnopqrstuvwxyz'

# Массив, содержащий относительную частоту каждой буквы в английском языке
english_frequences = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                      0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                      0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                      0.00978, 0.02360, 0.00150, 0.01974, 0.00074]


# Возвращает индекс вероятности для "раздела" данного зашифрованного текста
def get_index_c(ciphertext):
    N = float(len(ciphertext))
    frequency_sum = 0.0

    # Использование формулы индекса совпадения
    for letter in alphabet:
        frequency_sum += ciphertext.count(letter) * (ciphertext.count(letter) - 1)

    # Использование формулы индекса совпадения
    ic = frequency_sum / (N * (N - 1))
    return ic


# Возвращает длину ключа с наивысшим средним индексом совпадения
def get_key_length(ciphertext):
    ic_table = []

    # Разбивает зашифрованный текст на последовательности в зависимости от предполагаемой длины ключа от 0 до предполаг-
    # емой максимальной длины ключа (20)
    # Пример. угадывание длины ключа 2 разбивает «12345678» на «1357» и «2468»
    # Эта процедура разбиения зашифрованного текста на последовательности и сортировки по индексу совпадения
    # Предполагаемая длина ключа с наибольшим значением IC - это наиболее доступная длина ключа
    for guess_len in range(MAX_KEY_LENGTH_GUESS):
        ic_sum = 0.0
        avg_ic = 0.0
        for i in range(guess_len):
            sequence = ""
            # разбивает зашифрованный текст на последовательности
            for j in range(0, len(ciphertext[i:]), guess_len):
                sequence += ciphertext[i + j]
            ic_sum += get_index_c(sequence)
        # чтобы не делить на ноль
        if not guess_len == 0:
            avg_ic = ic_sum / guess_len
        ic_table.append(avg_ic)

    # возвращает индекс наивысшего индекса совпадения (наиболее вероятная длина ключа)
    best_guess = ic_table.index(sorted(ic_table, reverse=True)[0])
    second_best_guess = ic_table.index(sorted(ic_table, reverse=True)[1])

    # Поскольку эта программа может иногда думать, что ключ буквально дважды или трижды сам,
    # лучше вернуть меньшую сумму.
    # Пример. фактический ключ - «собака», но программа считает, что это «собака» или «собака».
    # (Причина этой ошибки в том, что распределение частот для ключевого слова «собака» и «собака» будет почти одинаковым)
    if best_guess % second_best_guess == 0:
        return second_best_guess
    else:
        return best_guess


# Выполняет частотный анализ "последовательности" зашифрованного текста, чтобы вернуть букву для этой части ключа
# Использует статистику хи-квадрат, чтобы измерить, насколько похожи два распределения вероятностей.
# (Два - зашифрованный текст и обычное английское распределение)
def freq_analysis(sequence):
    all_chi_squareds = [0] * 26

    for i in range(26):

        chi_squared_sum = 0.0

        # sequence_offset = [(((seq_ascii[j]-97-i)%26)+97) for j in range(len(seq_ascii))]
        sequence_offset = [chr(((ord(sequence[j]) - 97 - i) % 26) + 97) for j in range(len(sequence))]
        v = [0] * 26
        # подсчитываем числа каждой буквы в sequence_offset уже в ascii
        for l in sequence_offset:
            v[ord(l) - ord('a')] += 1
        # делим массив на длину последовательности, чтобы получить процентные значения частоты
        for j in range(26):
            v[j] *= (1.0 / float(len(sequence)))

        # теперь можно сравнить с английскими частотами
        for j in range(26):
            chi_squared_sum += ((v[j] - float(english_frequences[j])) ** 2) / float(english_frequences[j])

        # добавить его в большую таблицу коэффициентов ци-квадрат
        all_chi_squareds[i] = chi_squared_sum

    # вернуть букву ключа, которую нужно сдвинуть
    # определяется по наименьшей статистике хи-квадрат (наименьшая разница между распределением последовательностей и
    # английское распространение)
    shift = all_chi_squareds.index(min(all_chi_squareds))

    # вернуть письмо
    return chr(shift + 97)


def get_key(ciphertext, key_length):
    key = ''

    # Рассчитать таблицу частотности букв для каждой буквы ключа
    for i in range(key_length):
        sequence = ""
        # разбивает зашифрованный текст на последовательности
        for j in range(0, len(ciphertext[i:]), key_length):
            sequence += ciphertext[i + j]
        key += freq_analysis(sequence)

    return key


# Возвращает открытый текст по зашифрованному тексту и ключу
def decrypt(ciphertext, key):
    # Создает массив значений ascii зашифрованного текста и ключа
    cipher_ascii = [ord(letter) for letter in ciphertext]
    key_ascii = [ord(letter) for letter in key]
    plain_ascii = []

    # Превращает каждое значение ascii зашифрованного текста в значение ascii открытого текста
    for i in range(len(cipher_ascii)):
        plain_ascii.append(((cipher_ascii[i] - key_ascii[i % len(key)]) % 26) + 97)

    # Turns the array of ascii values into characters
    plaintext = ''.join(chr(i) for i in plain_ascii)
    return plaintext


def encrypt(plaintext, key):
    # Creates an array of the ascii values of the plaintext and the key
    plain_ascii = [ord(letter) for letter in plaintext]
    key_ascii = [ord(letter) for letter in key]
    cipher_ascii = []

    # Turns each ascii value of the plaintext into the ascii value of the ciphertext
    for i in range(len(plain_ascii)):

        temp = plain_ascii[i] + key_ascii[i % len(key)] - 97
        if temp > 122:
            # Loop back to the beginning of the alphabet
            cipher_ascii.append(temp - 26)
        else:
            cipher_ascii.append(temp)

    # Turns the array of ascii values into characters
    ciphertext = ''.join(chr(i) for i in cipher_ascii)
    return ciphertext


def main():
    choice = 1
    while choice != 0:
        print("Меню шифра Виженера")
        print("0. Выход из программы")
        print("1. Зашифровать")
        print("2. Дешифровать")
        choice = int(input("Введите число выбора: "))
        if choice == 1:
            plaintext_unfiltered = raw_input("Введите сообщение: ")
            key_unfiltered = raw_input("Введите ключ: ")
            plaintext = ''.join(x.lower() for x in plaintext_unfiltered if x.isalpha())
            key = ''.join(x.lower() for x in key_unfiltered if x.isalpha())
            print('ключ: ', key)

            ciphertext = encrypt(plaintext, key)
            print("Шифр: {} \n".format(ciphertext))

        elif choice == 2:
            ciphertext_unfiltered = raw_input("Введите текст для дешифровки: ")
            ciphertext = ''.join(x.lower() for x in ciphertext_unfiltered if x.isalpha())
            key_unfiltered = raw_input("Введите ключ: ")
            key = ''.join(x.lower() for x in key_unfiltered if x.isalpha())
            plaintext = decrypt(ciphertext, key)
            print("Текст: {}\n".format(plaintext))
        elif choice == 0:
            print("Программа отключена ! ")
        elif choice != 0 or 1 or 2:
            print("Неправильный ввод! \n")


if __name__ == '__main__':
    main()

