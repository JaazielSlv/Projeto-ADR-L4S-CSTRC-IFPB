################################################################################
# Script de Treinamento do Modelo de IA (Machine Learning)
################################################################################
# Este script deve ser executado no HOST (Windows) após a geração do dataset.
# Funcionalidades:
# 1. Carrega o arquivo 'dataset_l4s_final.csv'.
# 2. Seleciona as features relevantes (RTT, Throughput, CE Marks, etc.).
# 3. Treina um classificador Decision Tree (Árvore de Decisão).
# 4. Avalia a precisão do modelo e exibe as regras aprendidas (White-Box).
# 5. Salva o modelo treinado em 'l4s_detection_model.pkl' para uso no Router.
################################################################################

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import joblib
import os

# --- CONFIGURAÇÕES ---
# Garante que o caminho seja relativo ao local deste script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(SCRIPT_DIR, '../../dataset/dataset_l4s_final.csv')
MODEL_OUTPUT_PATH = os.path.join(SCRIPT_DIR, 'l4s_detection_model.pkl')

def train_and_evaluate():
    # 1. Carregar o Dataset
    if not os.path.exists(DATASET_PATH):
        print(f"[ERRO] Dataset não encontrado em: {DATASET_PATH}")
        print("Certifique-se de ter rodado o experimento e gerado o arquivo CSV.")
        return

    print(f"[*] Carregando dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)

    # Limpeza básica (remover linhas com NaN se houver)
    df = df.dropna()

    # 2. Seleção de Features (X) e Target (y)
    # Selecionamos as métricas validadas no dataset 'flow'
    features = [
        'flow_throughput_bps',
        'ratio_ect1',
        'ratio_ce',
        'flag_cwr',
        'ratio_cwr',
        'tcp_win_mean',
        'iat_mean',      # Jitter
        'pkt_len_mean'
    ]
    
    # Verifica se todas as colunas existem no CSV
    missing_cols = [col for col in features if col not in df.columns]
    if missing_cols:
        print(f"[ERRO] As seguintes colunas não foram encontradas no CSV: {missing_cols}")
        print(f"Colunas disponíveis: {list(df.columns)}")
        return

    X = df[features]
    y = df['label_is_attack'] # 0 = Benigno, 1 = Malicioso

    print(f"[*] Total de amostras: {len(df)}")
    print(f"[*] Distribuição das classes:\n{y.value_counts()}")

    # 3. Divisão Treino (70%) / Teste (30%)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    # 4. Treinamento da Árvore de Decisão
    print("[*] Treinando modelo Decision Tree...")
    # max_depth limita a profundidade para manter a interpretabilidade (evitar árvores gigantes)
    clf = DecisionTreeClassifier(criterion='gini', max_depth=5, random_state=42)
    clf.fit(X_train, y_train)

    # 5. Avaliação
    print("[*] Avaliando modelo...")
    y_pred = clf.predict(X_test)

    print("\n--- Relatório de Classificação ---")
    print(classification_report(y_test, y_pred, target_names=['Benigno', 'Malicioso']))

    print("\n--- Matriz de Confusão ---")
    print(confusion_matrix(y_test, y_pred))

    acc = accuracy_score(y_test, y_pred)
    print(f"\n[RESULTADO] Acurácia do Modelo: {acc:.2%}")

    # 6. Interpretabilidade (White-Box)
    print("\n--- Regras da Árvore (Texto) ---")
    tree_rules = export_text(clf, feature_names=features)
    print(tree_rules)

    # 7. Salvar o Modelo
    joblib.dump(clf, MODEL_OUTPUT_PATH)
    print(f"\n[*] Modelo salvo em: {MODEL_OUTPUT_PATH}")

    # Opcional: Plotar a árvore (se estiver rodando localmente com interface gráfica)
    # plt.figure(figsize=(20,10))
    # plot_tree(clf, feature_names=features, class_names=['Benigno', 'Malicioso'], filled=True)
    # plt.savefig('arvore_decisao.png')
    # print("[*] Imagem da árvore salva em 'arvore_decisao.png'")

if __name__ == "__main__":
    train_and_evaluate()
