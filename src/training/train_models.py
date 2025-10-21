"""
Model training script for the AI-powered IDS/IPS system.
Trains multiple ML models for intrusion detection and anomaly detection.
"""

import argparse
import json
import logging
import pickle
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import xgboost as xgb
import lightgbm as lgb
import joblib
import mlflow
import mlflow.sklearn
from mlflow.tracking import MlflowClient

from src.utils.config import Config
from src.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)


class ModelTrainer:
    """Main model training class."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.label_encoder = LabelEncoder()
        
        # Initialize MLflow
        mlflow.set_tracking_uri(self.config.model.model_registry_uri)
        self.client = MlflowClient()
    
    def load_data(self, data_path: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and preprocess training data.
        
        Args:
            data_path: Path to the training data file
            
        Returns:
            Tuple of (features, labels)
        """
        try:
            logger.info(f"Loading data from {data_path}")
            
            # Load data
            df = pd.read_csv(data_path)
            logger.info(f"Loaded data shape: {df.shape}")
            
            # Separate features and labels
            if 'Label' in df.columns:
                X = df.drop('Label', axis=1)
                y = df['Label']
            else:
                raise ValueError("Label column not found in dataset")
            
            # Handle missing values
            X = X.fillna(0)
            
            # Select numerical features only
            numerical_cols = X.select_dtypes(include=[np.number]).columns
            X = X[numerical_cols]
            
            # Store feature columns
            self.feature_columns = list(X.columns)
            
            logger.info(f"Features shape: {X.shape}")
            logger.info(f"Labels shape: {y.shape}")
            logger.info(f"Unique labels: {y.nunique()}")
            
            return X, y
        
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def preprocess_data(self, X: pd.DataFrame, y: pd.Series) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess data for training.
        
        Args:
            X: Feature matrix
            y: Label vector
            
        Returns:
            Tuple of (processed_features, processed_labels)
        """
        try:
            logger.info("Preprocessing data...")
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            self.scalers['standard'] = scaler
            
            # Encode labels
            y_encoded = self.label_encoder.fit_transform(y)
            self.encoders['label'] = self.label_encoder
            
            logger.info(f"Scaled features shape: {X_scaled.shape}")
            logger.info(f"Encoded labels shape: {y_encoded.shape}")
            
            return X_scaled, y_encoded
        
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}")
            raise
    
    def train_classification_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train classification models.
        
        Args:
            X: Feature matrix
            y: Label vector
            
        Returns:
            Dictionary of trained models
        """
        try:
            logger.info("Training classification models...")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            models = {}
            
            # Random Forest
            logger.info("Training Random Forest...")
            rf_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            rf_model.fit(X_train, y_train)
            models['random_forest'] = rf_model
            
            # XGBoost
            logger.info("Training XGBoost...")
            xgb_model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1
            )
            xgb_model.fit(X_train, y_train)
            models['xgboost'] = xgb_model
            
            # LightGBM
            logger.info("Training LightGBM...")
            lgb_model = lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1,
                verbose=-1
            )
            lgb_model.fit(X_train, y_train)
            models['lightgbm'] = lgb_model
            
            # Evaluate models
            results = {}
            for name, model in models.items():
                logger.info(f"Evaluating {name}...")
                
                # Predictions
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)
                
                # Metrics
                accuracy = model.score(X_test, y_test)
                auc_score = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')
                
                results[name] = {
                    'model': model,
                    'accuracy': accuracy,
                    'auc_score': auc_score,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba
                }
                
                logger.info(f"{name} - Accuracy: {accuracy:.4f}, AUC: {auc_score:.4f}")
            
            # Store models
            self.models.update(models)
            
            return results
        
        except Exception as e:
            logger.error(f"Error training classification models: {e}")
            raise
    
    def train_anomaly_detection_models(self, X: np.ndarray) -> Dict[str, Any]:
        """Train anomaly detection models.
        
        Args:
            X: Feature matrix
            
        Returns:
            Dictionary of trained anomaly detection models
        """
        try:
            logger.info("Training anomaly detection models...")
            
            models = {}
            
            # Isolation Forest
            logger.info("Training Isolation Forest...")
            iso_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            iso_forest.fit(X)
            models['isolation_forest'] = iso_forest
            
            # One-Class SVM
            logger.info("Training One-Class SVM...")
            oc_svm = OneClassSVM(
                nu=0.1,
                kernel='rbf',
                gamma='scale'
            )
            oc_svm.fit(X)
            models['one_class_svm'] = oc_svm
            
            # Store models
            self.models.update(models)
            
            return models
        
        except Exception as e:
            logger.error(f"Error training anomaly detection models: {e}")
            raise
    
    def hyperparameter_tuning(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Perform hyperparameter tuning for best model.
        
        Args:
            X: Feature matrix
            y: Label vector
            
        Returns:
            Dictionary of tuned models
        """
        try:
            logger.info("Performing hyperparameter tuning...")
            
            # Random Forest tuning
            logger.info("Tuning Random Forest...")
            rf_param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, 30],
                'min_samples_split': [2, 5, 10]
            }
            
            rf_grid = GridSearchCV(
                RandomForestClassifier(random_state=42, n_jobs=-1),
                rf_param_grid,
                cv=3,
                scoring='accuracy',
                n_jobs=-1
            )
            rf_grid.fit(X, y)
            
            logger.info(f"Best RF parameters: {rf_grid.best_params_}")
            logger.info(f"Best RF score: {rf_grid.best_score_:.4f}")
            
            # XGBoost tuning
            logger.info("Tuning XGBoost...")
            xgb_param_grid = {
                'n_estimators': [100, 200],
                'max_depth': [4, 6, 8],
                'learning_rate': [0.05, 0.1, 0.2]
            }
            
            xgb_grid = GridSearchCV(
                xgb.XGBClassifier(random_state=42, n_jobs=-1),
                xgb_param_grid,
                cv=3,
                scoring='accuracy',
                n_jobs=-1
            )
            xgb_grid.fit(X, y)
            
            logger.info(f"Best XGB parameters: {xgb_grid.best_params_}")
            logger.info(f"Best XGB score: {xgb_grid.best_score_:.4f}")
            
            return {
                'random_forest_tuned': rf_grid.best_estimator_,
                'xgboost_tuned': xgb_grid.best_estimator_
            }
        
        except Exception as e:
            logger.error(f"Error in hyperparameter tuning: {e}")
            raise
    
    def save_models(self, output_dir: str):
        """Save trained models and artifacts.
        
        Args:
            output_dir: Directory to save models
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Saving models to {output_path}")
            
            # Save models
            for name, model in self.models.items():
                model_path = output_path / f"{name}.pkl"
                joblib.dump(model, model_path)
                logger.info(f"Saved {name} to {model_path}")
            
            # Save scalers and encoders
            scaler_path = output_path / "scaler.pkl"
            joblib.dump(self.scalers['standard'], scaler_path)
            
            encoder_path = output_path / "label_encoder.pkl"
            joblib.dump(self.label_encoder, encoder_path)
            
            # Save feature columns
            feature_info = {
                'feature_columns': self.feature_columns,
                'num_features': len(self.feature_columns),
                'model_names': list(self.models.keys())
            }
            
            with open(output_path / "feature_info.json", 'w') as f:
                json.dump(feature_info, f, indent=2)
            
            logger.info("All models and artifacts saved successfully")
        
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            raise
    
    def log_to_mlflow(self, experiment_name: str, model_results: Dict[str, Any]):
        """Log training results to MLflow.
        
        Args:
            experiment_name: Name of the MLflow experiment
            model_results: Results from model training
        """
        try:
            logger.info(f"Logging to MLflow experiment: {experiment_name}")
            
            # Set experiment
            mlflow.set_experiment(experiment_name)
            
            with mlflow.start_run():
                # Log parameters
                mlflow.log_param("num_features", len(self.feature_columns))
                mlflow.log_param("num_models", len(self.models))
                
                # Log metrics
                for model_name, results in model_results.items():
                    if 'accuracy' in results:
                        mlflow.log_metric(f"{model_name}_accuracy", results['accuracy'])
                    if 'auc_score' in results:
                        mlflow.log_metric(f"{model_name}_auc", results['auc_score'])
                
                # Log models
                for name, model in self.models.items():
                    mlflow.sklearn.log_model(model, f"models/{name}")
                
                logger.info("Successfully logged to MLflow")
        
        except Exception as e:
            logger.error(f"Error logging to MLflow: {e}")
    
    def train_all_models(self, data_path: str, output_dir: str, experiment_name: str = "ids-ips-training"):
        """Train all models and save results.
        
        Args:
            data_path: Path to training data
            output_dir: Directory to save models
            experiment_name: MLflow experiment name
        """
        try:
            logger.info("Starting model training pipeline...")
            start_time = time.time()
            
            # Load and preprocess data
            X, y = self.load_data(data_path)
            X_scaled, y_encoded = self.preprocess_data(X, y)
            
            # Train classification models
            classification_results = self.train_classification_models(X_scaled, y_encoded)
            
            # Train anomaly detection models
            anomaly_results = self.train_anomaly_detection_models(X_scaled)
            
            # Hyperparameter tuning
            tuned_models = self.hyperparameter_tuning(X_scaled, y_encoded)
            self.models.update(tuned_models)
            
            # Save models
            self.save_models(output_dir)
            
            # Log to MLflow
            self.log_to_mlflow(experiment_name, classification_results)
            
            training_time = time.time() - start_time
            logger.info(f"Training completed in {training_time:.2f} seconds")
            
            return {
                'classification_results': classification_results,
                'anomaly_results': anomaly_results,
                'tuned_models': tuned_models,
                'training_time': training_time
            }
        
        except Exception as e:
            logger.error(f"Error in training pipeline: {e}")
            raise


def main():
    """Main training script."""
    parser = argparse.ArgumentParser(description='Train ML models for IDS/IPS')
    parser.add_argument('--data', required=True, help='Path to training data')
    parser.add_argument('--output', required=True, help='Output directory for models')
    parser.add_argument('--experiment', default='ids-ips-training', help='MLflow experiment name')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(log_level=args.log_level)
    logger = get_logger(__name__)
    
    try:
        # Initialize trainer
        trainer = ModelTrainer()
        
        # Train models
        results = trainer.train_all_models(
            data_path=args.data,
            output_dir=args.output,
            experiment_name=args.experiment
        )
        
        logger.info("Training completed successfully!")
        logger.info(f"Results: {results}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise


if __name__ == "__main__":
    main()
