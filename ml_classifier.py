"""
Módulo de Machine Learning para Clasificación de Vulnerabilidades SQL Injection
Entrena y utiliza modelos supervisados para clasificar endpoints
"""

import json
import pickle
import os
from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

class SQLInjectionMLClassifier:
    """Clasificador ML para detectar vulnerabilidades SQL Injection"""
    
    def __init__(self, model_type: str = 'random_forest'):
        """
        model_type: 'random_forest', 'gradient_boosting', o 'svm'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'response_time',
            'status_code',
            'response_length',
            'base_length_diff',
            'has_sql_error',
            'html_similarity',
            'dom_changes',
            'length_diff_ratio',
            'payload_type_basic',
            'payload_type_union',
            'payload_type_boolean',
            'payload_type_time',
            'payload_type_error'
        ]
        self.is_trained = False
    
    def extract_features(self, test_response: Dict, base_response: Dict, 
                        detector_result: Dict) -> np.ndarray:
        """
        Extrae características de una respuesta para el modelo ML
        """
        test_text = test_response.get('text', '')
        test_time = test_response.get('time', 0.0)
        test_status = test_response.get('status_code', 200)
        test_length = len(test_text)
        
        base_length = base_response.get('length', 0)
        base_length_diff = abs(test_length - base_length)
        length_diff_ratio = base_length_diff / base_length if base_length > 0 else 0.0
        
        # Detectar errores SQL
        from sqli_detector import SQLInjectionDetector
        detector = SQLInjectionDetector()
        has_sql_error = len(detector.detect_sql_errors(test_text)) > 0
        
        # Análisis HTML
        html_analysis = detector.analyze_html_changes(
            base_response.get('text', ''),
            test_text
        )
        html_similarity = html_analysis.get('similarity', 0.0)
        dom_changes = html_analysis.get('dom_changes', {})
        dom_changes_count = dom_changes.get('added', 0) + dom_changes.get('removed', 0)
        
        # Tipo de payload (one-hot encoding)
        payload_type = detector_result.get('payload_type', 'basic')
        payload_type_basic = 1 if payload_type == 'basic' else 0
        payload_type_union = 1 if payload_type == 'union' else 0
        payload_type_boolean = 1 if payload_type == 'boolean_blind' else 0
        payload_type_time = 1 if payload_type == 'time_based' else 0
        payload_type_error = 1 if payload_type == 'error_based' else 0
        
        features = np.array([
            test_time,
            test_status,
            test_length,
            base_length_diff,
            1 if has_sql_error else 0,
            html_similarity,
            dom_changes_count,
            length_diff_ratio,
            payload_type_basic,
            payload_type_union,
            payload_type_boolean,
            payload_type_time,
            payload_type_error
        ])
        
        return features
    
    def create_dataset(self, scan_results: List[Dict], detector_results: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Crea dataset de características y etiquetas desde resultados de escaneo
        """
        X = []
        y = []
        
        for scan_result, detector_result in zip(scan_results, detector_results):
            # Extraer características
            features = self.extract_features(
                scan_result,
                scan_result.get('base_response', {}),
                detector_result
            )
            X.append(features)
            
            # Etiqueta: 1 si vulnerable, 0 si no
            label = 1 if detector_result.get('vulnerable', False) else 0
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2):
        """
        Entrena el modelo con los datos proporcionados
        """
        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Escalar características
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Crear y entrenar modelo
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
        elif self.model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42
            )
        elif self.model_type == 'svm':
            self.model = SVC(
                kernel='rbf',
                probability=True,
                class_weight='balanced',
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        print(f"[*] Training {self.model_type} model...")
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluar
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"[+] Model accuracy: {accuracy:.2%}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Not Vulnerable', 'Vulnerable']))
        
        self.is_trained = True
        return accuracy
    
    def predict(self, test_response: Dict, base_response: Dict, 
               detector_result: Dict) -> Dict:
        """
        Predice si una respuesta es vulnerable usando el modelo entrenado
        """
        if not self.is_trained or self.model is None:
            return {
                'prediction': 'unknown',
                'probability': 0.0,
                'confidence': 'low',
                'message': 'Model not trained'
            }
        
        # Extraer características
        features = self.extract_features(test_response, base_response, detector_result)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Predecir
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        vuln_probability = probabilities[1] if len(probabilities) > 1 else 0.0
        
        # Determinar confianza
        if vuln_probability >= 0.9:
            confidence = 'high'
            pred_label = 'vulnerable'
        elif vuln_probability >= 0.5:
            confidence = 'medium'
            pred_label = 'potentially_vulnerable'
        else:
            confidence = 'low'
            pred_label = 'not_vulnerable'
        
        return {
            'prediction': pred_label,
            'probability': float(vuln_probability),
            'confidence': confidence,
            'raw_prediction': int(prediction)
        }
    
    def save_model(self, filepath: str):
        """Guarda el modelo entrenado"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"[+] Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Carga un modelo pre-entrenado"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.model_type = model_data['model_type']
        self.feature_names = model_data.get('feature_names', self.feature_names)
        self.is_trained = model_data.get('is_trained', True)
        
        print(f"[+] Model loaded from {filepath}")
    
    def generate_training_data_from_results(self, all_results: Dict) -> Tuple[np.ndarray, np.ndarray]:
        """
        Genera dataset de entrenamiento desde resultados de escaneo completos
        """
        X_list = []
        y_list = []
        
        from detector import SQLInjectionDetector
        detector = SQLInjectionDetector()
        
        for endpoint, endpoint_data in all_results.items():
            results = endpoint_data.get('results', [])
            
            for result in results:
                base_response = result.get('base_response', {})
                payload_info = result.get('payload_info', {})
                
                # Evaluar con detector
                detector_result = detector.evaluate_payload(
                    payload_info,
                    base_response,
                    result
                )
                
                # Extraer características
                features = self.extract_features(result, base_response, detector_result)
                X_list.append(features)
                
                # Etiqueta
                label = 1 if detector_result.get('vulnerable', False) else 0
                y_list.append(label)
        
        return np.array(X_list), np.array(y_list)

