import torch
import logging
from utils import blue, green
import numpy as np
from tqdm import tqdm
from scipy import sparse
import pdb


class MLPDataSet(torch.utils.data.Dataset):
    def __init__(self, X, y):
        if isinstance(X, np.ndarray):
            X = sparse.csr_matrix(X)
        self.X_total = X
        self.y_total = torch.tensor(y)

    def __getitem__(self, index):
        return torch.tensor(self.X_total[index].toarray().squeeze()), self.y_total[index]

    def __len__(self):
        return self.X_total.shape[0]


class MLPModel(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim=2):
        super(MLPModel, self).__init__()
        self.Linear1 = torch.nn.Linear(input_dim, hidden_dim)
        self.Relu1 = torch.nn.ReLU()
        self.dropout1 = torch.nn.Dropout()

        self.Linear2 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Relu2 = torch.nn.ReLU()
        self.dropout2 = torch.nn.Dropout()

        self.Linear3 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Relu3 = torch.nn.ReLU()
        self.dropout3 = torch.nn.Dropout()

        self.Linear4 = torch.nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        x_layer1 = self.dropout1(self.Relu1(self.Linear1(x)))
        x_layer2 = self.dropout2(self.Relu2(self.Linear2(x_layer1)))
        x_layer3 = self.dropout3(self.Relu3(self.Linear3(x_layer2)))
        logits = self.Linear4(x_layer3)
        return logits


class MLP:
    def __init__(self, input_dim=379, hidden=200, epochs=1, lr=0.001, batch_size=32):
        self.mlp = None
        self.input_dim = input_dim
        self.hidden = hidden
        self.epochs = epochs
        self.lr = lr
        self.batch_size = batch_size

    def fit(self, X, y):
        self.mlp = MLPModel(self.input_dim, self.hidden)
        self.mlp.train()
        self.mlp.cuda()
        mlp_optimizer = torch.optim.Adam(self.mlp.parameters(), lr=self.lr)
        mlp_dataset = MLPDataSet(X, y)
        mlp_loader = torch.utils.data.DataLoader(mlp_dataset, batch_size=self.batch_size, shuffle=True)
        for epoch in range(self.epochs):
            loss_total = []
            for batch_idx, (x_sample, y_sample) in enumerate(mlp_loader):
                mlp_optimizer.zero_grad()
                x_sample = x_sample.float().cuda()
                y_sample = y_sample.cuda()
                y_hat = self.mlp(x_sample)

                loss = torch.nn.CrossEntropyLoss()(y_hat, y_sample)
                loss.backward()
                mlp_optimizer.step()

                loss_total.append(loss.item())
                if batch_idx % 50 == 0:
                    logging.info(blue(
                        "Training MLP -------- Epoch: {}***Batch: {}, Loss: {}".format(epoch, batch_idx, loss.item())))

            logging.info(green("Epoch {} Finished! Average Loss :{}".format(epoch, np.mean(loss_total))))

    def predict(self, X):
        probability = self.predict_proba(X)
        return np.argmax(probability, axis=1)

    def predict_proba(self, X):
        with torch.no_grad():
            self.mlp.eval()
            self.mlp.cuda()
            if isinstance(X, np.ndarray):
                X = sparse.csr_matrix(X)
            total_predict = []
            for idx in tqdm(range(0, X.shape[0], self.batch_size)):
                x = torch.tensor(X[idx:idx + self.batch_size].toarray()).float().cuda()
                predict = torch.nn.functional.softmax(self.mlp(x), dim=1)
                total_predict.append(predict.cpu().detach())
            return torch.cat(total_predict).cpu().numpy()

    def predict_logits(self, X):
        with torch.no_grad():
            self.mlp.eval()
            self.mlp.cuda()
            if isinstance(X, np.ndarray):
                X = sparse.csr_matrix(X)
            total_logits = []
            for idx in tqdm(range(0, X.shape[0], self.batch_size)):
                x = torch.tensor(X[idx:idx + self.batch_size].toarray()).float().cuda()
                logits = self.mlp(x)
                total_logits.append(logits.cpu().detach())
            return torch.cat(total_logits).cpu().numpy()
