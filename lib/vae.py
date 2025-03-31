import random
import numpy as np
import torch
import logging
from utils import blue, green


class Encoder(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout, output_dim):
        super(Encoder, self).__init__()
        self.output_dim = output_dim
        self.Linear1 = torch.nn.Linear(input_dim, hidden_dim)
        self.Elu1 = torch.nn.ELU()
        self.dropout1 = torch.nn.Dropout(dropout)

        self.Linear2 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Tanh2 = torch.nn.Tanh()
        self.dropout2 = torch.nn.Dropout(dropout)

        self.Linear3 = torch.nn.Linear(hidden_dim, output_dim * 2)
        self.Softplus3 = torch.nn.Softplus()

    def forward(self, x):
        x_layer1 = self.dropout1(self.Elu1(self.Linear1(x)))
        x_layer2 = self.dropout2(self.Tanh2(self.Linear2(x_layer1)))
        x_layer3 = self.Linear3(x_layer2)

        mu = x_layer3[:, :self.output_dim]
        sigma = 1e-6 + self.Softplus3(x_layer3[:, self.output_dim:])
        return mu, sigma


class Decoder(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout, output_dim=379):
        super(Decoder, self).__init__()
        self.Linear1 = torch.nn.Linear(input_dim, hidden_dim)
        self.Tanh1 = torch.nn.Tanh()
        self.dropout1 = torch.nn.Dropout(dropout)

        self.Linear2 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Elu2 = torch.nn.ELU()
        self.dropout2 = torch.nn.Dropout(dropout)

        self.Linear3 = torch.nn.Linear(hidden_dim, output_dim)
        self.Sigmoid3 = torch.nn.Sigmoid()

    def forward(self, x):
        x_layer1 = self.dropout1(self.Tanh1(self.Linear1(x)))
        x_layer2 = self.dropout2(self.Elu2(self.Linear2(x_layer1)))
        x_layer3 = self.Sigmoid3(self.Linear3(x_layer2))
        vec = torch.clip(x_layer3, 1e-8, 1 - 1e-8)
        return vec


class MLP(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, dropout, output_dim=2):
        super(MLP, self).__init__()
        self.Linear1 = torch.nn.Linear(input_dim, hidden_dim)
        self.Tanh1 = torch.nn.Tanh()
        self.dropout1 = torch.nn.Dropout(dropout)

        self.Linear2 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Elu2 = torch.nn.ELU()
        self.dropout2 = torch.nn.Dropout(dropout)

        self.Linear3 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.Elu3 = torch.nn.ELU()
        self.dropout3 = torch.nn.Dropout(dropout)

        self.Linear4 = torch.nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        x_layer1 = self.dropout1(self.Tanh1(self.Linear1(x)))
        x_layer2 = self.dropout2(self.Elu2(self.Linear2(x_layer1)))
        x_layer3 = self.dropout3(self.Elu3(self.Linear3(x_layer2)))
        logits = self.Linear4(x_layer3)
        return logits


class FDVAEDataSet(torch.utils.data.Dataset):
    def __init__(self, X, y):
        super(FDVAEDataSet, self).__init__()
        self.X_total = torch.tensor(X)
        self.y_total = torch.tensor(y)
        self.data_total = []
        self.data_total_bak = []
        self.data_benign = []
        self.data_malicious = []
        for data, label in zip(self.X_total, self.y_total):
            if label == 0:
                self.data_benign.append((data, label))
            else:
                self.data_malicious.append((data, label))
        self.regenerate_data_total()

    def __getitem__(self, index):
        benign_sample, malicious_sample = self.data_total[index]
        benign_sample_bak, malicious_sample_bak = self.data_total_bak[index]
        return torch.stack([benign_sample[0], benign_sample[0]]), torch.stack(
            [benign_sample[0], malicious_sample[0]]), torch.cat(
            [benign_sample[1].unsqueeze(dim=0), malicious_sample[1].unsqueeze(dim=0)]), torch.stack(
            [benign_sample_bak[0], malicious_sample_bak[0]]), torch.cat(
            [benign_sample_bak[1].unsqueeze(dim=0), malicious_sample_bak[1].unsqueeze(dim=0)])

    def __len__(self):
        return len(self.data_total)

    def regenerate_data_total(self):
        self.data_total = []
        self.data_total_bak = []
        random.shuffle(self.data_benign)
        random.shuffle(self.data_malicious)
        for benign_sample, malicious_sample in zip(self.data_benign, self.data_malicious):
            self.data_total.append((benign_sample, malicious_sample))
        random.shuffle(self.data_benign)
        random.shuffle(self.data_malicious)
        for benign_sample, malicious_sample in zip(self.data_benign, self.data_malicious):
            self.data_total_bak.append((benign_sample, malicious_sample))


class MLPDataSet(torch.utils.data.Dataset):
    def __init__(self, X, y):
        self.X_total = torch.tensor(X)
        self.y_total = torch.tensor(y)
        self.data_total = []
        self.data_benign = []
        self.data_malicious = []
        for data, label in zip(self.X_total, self.y_total):
            if label.item() == 0:
                self.data_benign.append((data, label))
            else:
                self.data_malicious.append((data, label))
        self.reload_data()

    def __getitem__(self, index):
        benign_sample, malicious_sample = self.data_total[index]
        return torch.stack([benign_sample[0], malicious_sample[0]]), torch.cat(
            [benign_sample[1].unsqueeze(dim=0), malicious_sample[1].unsqueeze(dim=0)])

    def __len__(self):
        return len(self.data_total)

    def reload_data(self):
        self.data_total = []
        random.shuffle(self.data_benign)
        random.shuffle(self.data_malicious)
        for benign_sample, malicious_sample in zip(self.data_benign, self.data_malicious):
            self.data_total.append((benign_sample, malicious_sample))


class MLPDataSetBack(torch.utils.data.Dataset):
    def __init__(self, X, y):
        self.X_total = torch.tensor(X)
        self.y_total = torch.tensor(y)

    def __getitem__(self, index):
        return self.X_total[index], self.y_total[index]

    def __len__(self):
        return len(self.X_total)


class FD_VAE_MLP:
    def __init__(self, vae_hidden=600, dim_z=80, mlp_hidden=40,
                 vae_batch_size=128, mlp_batch_size=64,
                 vae_lr=0.001, mlp_lr=0.001,
                 vae_epochs=50, mlp_epochs=20,
                 vae_dropout=0.1, mlp_dropout=0.1,
                 lambda1=10, lambda2=1, lambda3=10):
        self.encoder = None
        self.decoder = None
        self.mlp = None
        # vae hyperparameter
        self.vae_hidden = vae_hidden
        self.dim_z = dim_z
        self.vae_batch_size = vae_batch_size
        self.vae_lr = vae_lr
        self.vae_epochs = vae_epochs
        self.vae_dropout = vae_dropout
        self.lambda1 = lambda1
        self.lambda2 = lambda2
        self.lambda3 = lambda3

        # mlp hyperparameter
        self.mlp_hidden = mlp_hidden
        self.mlp_batch_size = mlp_batch_size
        self.mlp_lr = mlp_lr
        self.mlp_epochs = mlp_epochs
        self.mlp_dropout = mlp_dropout

    def fit(self, X, y):
        self.encoder = Encoder(input_dim=379, hidden_dim=self.vae_hidden, dropout=self.vae_dropout,
                               output_dim=self.dim_z)
        self.decoder = Decoder(input_dim=self.dim_z, hidden_dim=self.vae_hidden, dropout=self.vae_dropout)
        self.mlp = MLP(input_dim=self.dim_z * 2, hidden_dim=self.mlp_hidden, dropout=self.mlp_dropout)

        # train fd-vae
        self.encoder.train()
        self.encoder.cuda()
        self.decoder.train()
        self.decoder.cuda()

        encoder_optimizer = torch.optim.Adam(self.encoder.parameters(), lr=self.vae_lr)
        decoder_optimizer = torch.optim.Adam(self.decoder.parameters(), lr=self.vae_lr)

        vae_dataset = FDVAEDataSet(X, y)
        vae_loader = torch.utils.data.DataLoader(vae_dataset, batch_size=self.vae_batch_size, shuffle=False)
        for epoch in range(self.vae_epochs):
            loss1_total = []
            loss2_total = []
            loss3_total = []
            loss_total = []
            for batch_idx, (x_benign, omega_x, omega_y, delta_x, delta_y) in enumerate(vae_loader):
                encoder_optimizer.zero_grad()
                decoder_optimizer.zero_grad()

                x_benign = x_benign.reshape(-1, x_benign.shape[-1])
                omega_x = omega_x.reshape(-1, omega_x.shape[-1])
                omega_y = omega_y.flatten()
                delta_x = delta_x.reshape(-1, delta_x.shape[-1])
                delta_y = delta_y.flatten()

                omega_data = []
                delta_data = []
                for data in zip(omega_x, omega_y):
                    omega_data.append(data)
                for data in zip(delta_x, delta_y):
                    delta_data.append(data)
                random.shuffle(omega_data)
                random.shuffle(delta_data)

                x_benign = x_benign.float().cuda()
                omega_x = torch.stack([x[0] for x in omega_data]).float().cuda()
                omega_y = torch.tensor([x[1] for x in omega_data]).cuda()

                delta_x = torch.stack([x[0] for x in delta_data]).float().cuda()
                delta_y = torch.tensor([x[1] for x in delta_data]).cuda()

                mu_x, sigma_x = self.encoder(x_benign)
                z = mu_x + sigma_x * torch.randn(mu_x.shape).cuda()
                x_benign_reconstruct = self.decoder(z)

                loss1 = -torch.mean(
                    torch.sum(x_benign * torch.log(x_benign_reconstruct + 1e-8) + (1 - x_benign) * torch.log(
                        1 - x_benign_reconstruct + 1e-8), dim=1))
                loss2 = 0.5 * torch.mean(torch.sum(
                    torch.square(mu_x) + torch.square(sigma_x) - torch.log(1e-8 + torch.square(sigma_x)) - 1, dim=1))

                mu_omega, sigma_omega = self.encoder(omega_x)
                mu_delta, sigma_delta = self.encoder(delta_x)

                label_consists = torch.square(omega_y - delta_y)
                k = 60 * label_consists
                mse_mu = torch.mean(torch.square(mu_omega - mu_delta), dim=1)
                loss3_equal = torch.mean(mse_mu * (1 - label_consists))
                loss3_unequal = torch.mean(torch.nn.functional.relu(k - mse_mu) * label_consists)
                loss3 = loss3_equal + loss3_unequal

                loss = self.lambda1 * loss1 + self.lambda2 * loss2 + self.lambda3 * loss3
                loss.backward()

                encoder_optimizer.step()
                decoder_optimizer.step()

                loss1_total.append(loss1.item())
                loss2_total.append(loss2.item())
                loss3_total.append(loss3.item())
                loss_total.append(loss.item())
                if batch_idx % 50 == 0:
                    logging.info(blue(
                        "Training VAE -------- Epoch: {}***Batch: {}, \nLoss-1: {}, \nLoss-2: {}, \nLoss-3: {}, \nTotal Loss: {}".format(
                            epoch, batch_idx, loss1.item(), loss2.item(), loss3.item(), loss.item())))

            logging.info(green(
                "Epoch {} Finished! \nAverage Loss 1:{} \nAverage Loss 2:{} \nAverage Loss 3:{} \nAverage Loss Total:{}".format(
                    epoch, np.mean(loss1_total), np.mean(loss2_total), np.mean(loss3_total), np.mean(loss_total))))

            vae_loader.dataset.regenerate_data_total()

        # train mlp
        self.encoder.eval()
        self.mlp.train()
        self.mlp.cuda()
        mlp_optimizer = torch.optim.Adam(self.mlp.parameters(), lr=self.mlp_lr)

        mlp_dataset = MLPDataSet(X, y)
        mlp_loader = torch.utils.data.DataLoader(mlp_dataset, batch_size=self.mlp_batch_size, shuffle=False)
        # mlp_dataset_back = MLPDataSetBack(X, y)
        # mlp_loader_back = torch.utils.data.DataLoader(mlp_dataset_back, batch_size=self.mlp_batch_size, shuffle=True)
        for epoch in range(self.mlp_epochs):
            loss_total = []
            for batch_idx, (x_sample, y_sample) in enumerate(mlp_loader):
                # for batch_idx, (x_sample, y_sample) in enumerate(mlp_loader_back):
                mlp_optimizer.zero_grad()
                x_sample = x_sample.reshape(-1, x_sample.shape[-1])
                y_sample = y_sample.flatten()

                x_sample = x_sample.float().cuda()
                y_sample = torch.eye(2)[y_sample].cuda()
                with torch.no_grad():
                    mu, sigma = self.encoder(x_sample)
                    mu_sigma = torch.cat([mu, sigma], dim=1)
                y_hat = self.mlp(mu_sigma)
                loss = torch.mean(
                    -y_sample * torch.log(torch.sigmoid(y_hat)) - (1 - y_sample) * torch.log(1 - torch.sigmoid(y_hat)))
                loss.backward()
                mlp_optimizer.step()

                loss_total.append(loss.item())
                if batch_idx % 50 == 0:
                    logging.info(blue(
                        "Training MLP -------- Epoch: {}***Batch: {}, Loss: {}".format(epoch, batch_idx, loss.item())))

            logging.info(green("Epoch {} Finished! Average Loss :{}".format(epoch, np.mean(loss_total))))

            mlp_loader.dataset.reload_data()

    def predict(self, X, threshold=30):
        with torch.no_grad():
            self.encoder.eval()
            self.encoder.cuda()
            self.decoder.eval()
            self.decoder.cuda()
            self.mlp.eval()
            self.mlp.cuda()
            X = torch.tensor(X).float().cuda()
            if len(X.shape) == 1:
                X = torch.unsqueeze(X, dim=0)
            mu, sigma = self.encoder(X)
            mu_sigma = torch.cat([mu, sigma], dim=1)
            y_mlp = torch.argmax(self.mlp(mu_sigma), axis=1)

            z = mu + sigma * torch.randn(mu.shape).cuda()
            y_reconstruct = self.decoder(z)
            L1 = -torch.sum(X * torch.log(y_reconstruct + 1e-8) + (1 - X) * torch.log(1 - y_reconstruct + 1e-8), dim=1)
            # L2 = 0.5 * torch.sum(torch.square(mu) + torch.square(sigma) - torch.log(1e-8 + torch.square(sigma)) - 1,
            #                      dim=1)
            # L = L1 + L2
            L = L1
            y_vae = L >= threshold
            assert y_mlp.shape == y_vae.shape
            final_label = []
            for vae_label, mlp_label in zip(y_vae, y_mlp):
                if vae_label:
                    final_label.append(1)
                else:
                    final_label.append(mlp_label.item())
            return np.array(final_label)

    def predict_proba(self, X, threshold=30):
        with torch.no_grad():
            self.encoder.eval()
            self.encoder.cuda()
            self.decoder.eval()
            self.decoder.cuda()
            self.mlp.eval()
            self.mlp.cuda()
            X = torch.tensor(X).float().cuda()
            if len(X.shape) == 1:
                X = torch.unsqueeze(X, dim=0)
            mu, sigma = self.encoder(X)
            mu_sigma = torch.cat([mu, sigma], dim=1)
            y_mlp = torch.sigmoid(self.mlp(mu_sigma))

            z = mu + sigma * torch.randn(mu.shape).cuda()
            y_reconstruct = self.decoder(z)
            L1 = -torch.sum(X * torch.log(y_reconstruct + 1e-8) + (1 - X) * torch.log(1 - y_reconstruct + 1e-8), dim=1)
            # L2 = 0.5 * torch.sum(torch.square(mu) + torch.square(sigma) - torch.log(1e-8 + torch.square(sigma)) - 1,
            #                      dim=1)
            # L = L1 + L2
            L = L1
            y_vae = L >= threshold

            final_logits = []
            for vae_label, mlp_logits in zip(y_vae, y_mlp):
                if vae_label:
                    final_logits.append(np.array([0.0, 1.0]))
                else:
                    final_logits.append(mlp_logits.cpu().numpy())
            return np.array(final_logits)
